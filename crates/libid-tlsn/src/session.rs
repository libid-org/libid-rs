//! MPC-TLS session setup and execution for both prover and verifier.

use http_body_util::BodyExt;
use hyper::{
    body::Bytes,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use libid_transcript::ceremony::Layout;
use std::future::IntoFuture;
use tlsn::{
    attestation::{
        request::{
            Request,
            RequestConfig,
        },
        signing::SignatureAlgId,
        CryptoProvider,
        Secrets,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::{
        CertBinding,
        CertBindingV1_2,
        HandshakeData,
        ServerName,
    },
    hash::HashAlgId,
    prover::ProverOutput,
    transcript::{
        Direction,
        PartialTranscript,
        TlsTranscript,
        TranscriptCommitConfig,
        TranscriptCommitment,
        TranscriptSecret,
    },
    verifier::{
        VerifierCommitStart,
        VerifierOutput,
    },
    webpki::{
        CertificateDer,
        RootCertStore,
    },
    Session,
};
use tokio::{
    io::{
        AsyncRead,
        AsyncWrite,
    },
    task::{
        JoinError,
        JoinHandle,
    },
};
use tokio_util::compat::{
    Compat,
    FuturesAsyncReadCompatExt,
    TokioAsyncReadCompatExt,
};
use tracing::{
    info,
    instrument,
};

use libid_transcript::{
    find_notary_reveal_ranges,
    find_presentation_commit_ranges,
    TlsHandshakeData,
};

use crate::{
    Error,
    Result,
};

/// Maximum bytes the prover may send in the MPC-TLS session (4 KB). The
/// verifier rejects sessions configured above this.
pub const MAX_SENT_DATA: usize = 1 << 12;
/// Maximum bytes the prover may receive in the MPC-TLS session (32 KB). The
/// verifier rejects sessions configured above this.
pub const MAX_RECV_DATA: usize = 1 << 15;

/// Owns a spawned task and aborts it on drop unless the handle was taken back
/// out with [`AbortOnDrop::into_inner`].
///
/// Dropping a bare [`JoinHandle`] DETACHES the task rather than cancelling
/// it, so every `?` early return in the session functions below would leave
/// the spawned driver running unsupervised — each aborted connection (e.g. a
/// kubelet `tcpSocket` health probe) then retains the task and its MPC
/// buffers. With this guard, cancellation is the default on every exit path,
/// including panics and the caller dropping the session future; the success
/// path opts out by taking the handle back to join it.
struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    /// The wrapped handle, for polling the task without disarming the guard.
    fn handle_mut(&mut self) -> &mut JoinHandle<T> {
        self.0.as_mut().expect("handle present until into_inner")
    }

    /// Disarm the guard and hand the handle back for joining.
    fn into_inner(mut self) -> JoinHandle<T> {
        self.0.take().expect("handle present until into_inner")
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Error for a session driver that finished while session setup was still in
/// flight. The driver only completes once the underlying socket is closed or
/// dead, so a protocol request submitted to it may never resolve — the racy
/// wedge behind the notary health-probe leak: without this check,
/// [`verifier`] could pend forever on a connection that closed immediately.
fn driver_finished_early<T, E: std::fmt::Display>(
    result: std::result::Result<std::result::Result<T, E>, JoinError>,
) -> Error {
    let detail = match result {
        Ok(Ok(_)) => "driver task finished before the session completed".into(),
        Ok(Err(e)) => format!("driver task: {e}"),
        Err(e) => format!("driver task join: {e}"),
    };
    Error::MpcTlsFailed { detail }
}

/// The WebPKI root store both sides validate server certificates against.
pub fn root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|c| CertificateDer(c.to_vec()))
            .collect(),
    }
}

/// Extract TLS handshake data from a TLS transcript.
pub fn extract_handshake_data(
    tls_transcript: &TlsTranscript,
) -> Result<TlsHandshakeData> {
    let CertBinding::V1_2(CertBindingV1_2 {
        client_random,
        server_random,
        server_ephemeral_key,
    }) = tls_transcript.certificate_binding()
    else {
        return Err(Error::UnsupportedTlsVersion {
            detail: "expected TLS 1.2".into(),
        });
    };

    Ok(TlsHandshakeData {
        client_random: *client_random,
        server_random: *server_random,
        server_ephemeral_key: server_ephemeral_key.key.clone(),
    })
}

/// A phase boundary of a prover session, in the order they occur.
///
/// Reported through `on_progress` so a caller can drive something typed off
/// them -- a progress indicator for a browser waiting out a server-side
/// exchange, which takes seconds. The same four boundaries are `tracing`
/// events for operators; this is the interface, because log text is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProverStep {
    /// MPC-TLS session established with the notary.
    MpcSetupComplete,
    /// TLS handshake completed through it.
    TlsHandshakeComplete,
    /// The platform answered.
    PlatformDataFetched,
    /// The proof is finalised and the session can be closed.
    MpcProofFinalized,
}

impl ProverStep {
    /// How far through the session this boundary is, in `(0, 1]`.
    ///
    /// The phases are not equal in wall-clock time -- setup and proving
    /// dominate -- so this is a position, not an estimate of remaining time.
    pub fn fraction(self) -> f32 {
        match self {
            Self::MpcSetupComplete => 0.25,
            Self::TlsHandshakeComplete => 0.5,
            Self::PlatformDataFetched => 0.75,
            Self::MpcProofFinalized => 1.0,
        }
    }
}

/// The blinder that opens one commitment this session made.
///
/// A committed range is a hash of the plaintext and this value, so the party
/// that later proves something about those bytes needs both. The prover is the
/// only party that ever holds it: the notary sees the commitment, never the
/// opening, which is the whole point of committing rather than revealing.
///
/// It is surfaced because a caller that commits a credential must hand the
/// opening on to whoever proves over it — the browser, for a bearer this
/// service exchanged. Without it the caller holds an attestation nobody can
/// build a proof against.
#[derive(Clone)]
pub struct CommitmentOpening {
    /// Which direction of the transcript the committed range belongs to.
    pub direction: Direction,
    /// The committed ranges, in the same shape the layout stated them, so a
    /// caller can match an opening against the range it asked to commit
    /// without converting anything.
    pub ranges: Vec<std::ops::Range<usize>>,
    /// The blinder itself. Sixteen bytes, as the commitment scheme fixes.
    pub blinder: Vec<u8>,
}

/// Result from the MPC-TLS prover.
pub struct ProverResult<T> {
    /// The HTTP response body from the platform API (decoded, headers stripped).
    pub response_body: Vec<u8>,
    /// The TLS secrets for proof construction.
    pub secrets: Secrets,
    /// Extracted TLS handshake data.
    pub handshake: TlsHandshakeData,
    /// One opening per commitment this session made, in the order the layouts
    /// stated them. Empty when the session committed nothing.
    pub commitment_openings: Vec<CommitmentOpening>,
    /// The recovered I/O stream after MPC-TLS completes.
    pub recovered_io: T,
}

/// Result from the MPC-TLS verifier (notary).
pub struct VerifierResult<T> {
    /// The partial transcript with revealed data.
    pub partial_transcript: PartialTranscript,
    /// The server name from the TLS handshake.
    pub server_name: ServerName,
    /// The full TLS transcript.
    pub tls_transcript: TlsTranscript,
    /// The transcript commitments for proof verification.
    pub transcript_commitments: Vec<TranscriptCommitment>,
    /// The recovered I/O stream after MPC-TLS completes.
    pub recovered_io: T,
}

/// Parameters for the user-info prover flow ([`prover`]).
#[derive(Debug, Clone, Copy)]
pub struct UserInfoParams<'a> {
    /// API host (SNI and Host header).
    pub api_host: &'a str,
    /// Path of the user-info endpoint, e.g. `"/2/users/me"`.
    pub user_info_path: &'a str,
    /// JSON field holding the handle; its `"field":"value"` snippet is
    /// revealed.
    pub username_field: &'a str,
    /// Optional immutable-id field: `(field_name, quoted)`. Quoted (X):
    /// `"id":"<id>"`; bare (GitHub): `"id":<n>,`. Revealed when present so
    /// the backend can build idPath.
    pub id_field: Option<(&'a str, bool)>,
    /// User-Agent header value.
    pub user_agent: &'a str,
}

/// Run the MPC-TLS prover to fetch user data from a platform API, revealing
/// the username snippet (and the id snippet when configured).
#[instrument(skip_all, fields(api_host = params.api_host))]
pub async fn prover<T>(
    socket: T,
    access_token: &str,
    params: &UserInfoParams<'_>,
) -> Result<ProverResult<T>>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let username_field = params.username_field;
    let id_field = params.id_field;
    // The headers this flow sends, stated here rather than injected by the
    // library. A notarized request is bytes a verifier compares against a
    // profile, so whoever knows the profile writes them.
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!(
            "https://{}{}",
            params.api_host, params.user_info_path
        ))
        .header("Host", params.api_host)
        .header("Connection", "close")
        .header("Accept", "application/json")
        .header("User-Agent", params.user_agent)
        .header("Authorization", format!("Bearer {access_token}"))
        .body(http_body_util::Full::new(Bytes::new()))
        .map_err(|e| Error::MpcTlsFailed {
            detail: format!("request build: {e}"),
        })?;

    prover_generic(
        socket,
        request,
        // This flow predates the ceremony layouts and still selects the old
        // sparse ranges: the request line and `Host` revealed, everything else
        // of the response committed whole. It does NOT tile, so what it
        // produces is not a ceremony attestation. It goes at cutover.
        |sent, recv| {
            let mut ranges =
                vec![
                    libid_transcript::compute_field_snippet_range(recv, username_field)
                        .ok_or_else(|| Error::MpcTlsFailed {
                        detail: format!(
                            "username field '{}' not found in response body",
                            username_field
                        ),
                    })?,
                ];
            // Also reveal the immutable id snippet so the backend can build idPath.
            // Quoted (X): `"id":"<id>"`; bare (GitHub): `"id":<n>,`.
            if let Some((id_field, quoted)) = id_field {
                if let Some(range) =
                    libid_transcript::compute_id_snippet_range(recv, id_field, quoted)
                {
                    ranges.push(range);
                }
            }
            Ok((
                Layout {
                    reveal: find_notary_reveal_ranges(sent),
                    commit: find_presentation_commit_ranges(sent),
                },
                Layout {
                    reveal: ranges,
                    commit: core::iter::once(0..recv.len()).collect(),
                },
            ))
        },
        // This flow goes at cutover and nothing watches it run.
        |_| {},
    )
    .await
}

/// Run the MPC-TLS prover with arbitrary API parameters.
///
/// `select_layout` receives both complete transcripts once the HTTP exchange
/// finishes and returns, for each direction, what to reveal and what to commit.
/// The prover chooses that -- it is the party holding the session keys, and
/// nobody above it can decide on its behalf.
///
/// A caller producing a ceremony attestation calls
/// `libid_transcript::ceremony` here and returns what it gives back: those
/// layouts derive each direction's commitments as the complement of its
/// reveals, so the direction tiles by construction, which is what the Platform
/// Verifier's coverage check demands. A caller doing something else -- the
/// JWKS session reads a public document and reveals all of it -- states its
/// own.
///
/// Each revealed range becomes a separate Merkle leaf in the notary's
/// transcript tree. [`libid_transcript::compute_field_reveal_range`] and
/// friends locate JSON field values in a response body.
///
/// # Following a session
///
/// This is slow -- setup and proving dominate -- so every phase boundary is
/// reported twice, to two different audiences. A `tracing` event inside this
/// function's span, for whoever reads the logs; and [`ProverStep`] through
/// `on_progress`, for a caller driving something typed off it.
///
/// The browser has its own progress from the tlsn wasm prover and never
/// reaches this function. The caller this exists for is a server that
/// notarizes on someone's behalf -- the GitHub Token-Exchange Service, whose
/// HTTP caller waits out the whole session -- and which cannot report phases
/// by parsing log lines.
#[instrument(skip_all)]
pub async fn prover_generic<T, S, F>(
    socket: T,
    request: hyper::Request<http_body_util::Full<Bytes>>,
    select_layout: S,
    on_progress: F,
) -> Result<ProverResult<T>>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    S: FnOnce(&[u8], &[u8]) -> Result<(Layout, Layout)>,
    F: Fn(ProverStep),
{
    // SNI and the TCP peer come from the request's own authority. A caller
    // that set no host has not said which server it means to reach.
    let api_host = request
        .uri()
        .host()
        .ok_or_else(|| Error::MpcTlsFailed {
            detail: "request URI carries no host".into(),
        })?
        .to_string();
    let api_host = api_host.as_str();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let mut driver_task = AbortOnDrop::new(tokio::spawn(driver));

    let setup = async {
        info!("Setting up MPC-TLS");
        let prover = handle
            .new_prover(ProverConfig::builder().build().map_err(|e| {
                Error::MpcTlsFailed {
                    detail: format!("prover config: {e}"),
                }
            })?)
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("new prover: {e}"),
            })?
            .commit(
                MpcTlsConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_recv_data(MAX_RECV_DATA)
                    .build()
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("mpc tls config: {e}"),
                    })?,
            )
            .await
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("commit: {e}"),
            })?;
        info!("MPC-TLS setup complete");
        on_progress(ProverStep::MpcSetupComplete);

        info!("Connecting to {} API", api_host);
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", api_host)).await?;
        let (tls, prover) = prover
            .connect(
                TlsClientConfig::builder()
                    .server_name(ServerName::Dns(api_host.try_into().map_err(|e| {
                        Error::MpcTlsFailed {
                            detail: format!("server name: {e}"),
                        }
                    })?))
                    .root_store(root_store())
                    .build()
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("tls client config: {e}"),
                    })?,
                tcp.compat(),
            )
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("connect: {e}"),
            })?;
        info!("TLS handshake complete");
        on_progress(ProverStep::TlsHandshakeComplete);

        let prover_task = AbortOnDrop::new(tokio::spawn(prover.into_future()));
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls.compat()))
                .await
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("http handshake: {e}"),
                })?;
        // The HTTP connection task normally finishes with the `Connection: close`
        // exchange; the guard reaps it if the session bails out first.
        let _conn_task = AbortOnDrop::new(tokio::spawn(conn));

        info!("Sending {method} {path}");
        let response =
            sender
                .send_request(request)
                .await
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("send request: {e}"),
                })?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("collect body: {e}"),
            })?
            .to_bytes();
        if status != StatusCode::OK {
            return Err(Error::MpcTlsFailed {
                detail: format!(
                    "API returned {}: {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
            });
        }
        info!("Response: {} bytes", body.len());
        on_progress(ProverStep::PlatformDataFetched);

        let mut prover = prover_task
            .into_inner()
            .await
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("prover task join: {e}"),
            })?
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("prover task: {e}"),
            })?;
        let transcript = prover.transcript().clone();
        let sent = transcript.sent();
        let recv = transcript.received();
        // The ceremony layouts derive their commitments as the complement of
        // the reveals, so each direction tiles by construction -- which is what
        // the Platform Verifier's coverage check demands.
        // The prover chooses what it reveals -- that is what a prover IS. One
        // parameter says so, and there is no second mechanism to disagree with
        // it. A caller wanting the specification's layouts calls
        // `libid_transcript::ceremony` here and returns what it gives back.
        let (sent_layout, recv_layout) = select_layout(sent, recv)?;

        let reveal_recv_ranges = recv_layout.reveal.clone();

        let notary_sent_ranges = sent_layout.reveal.clone();

        let mut tc_builder = TranscriptCommitConfig::builder(&transcript);
        let (sent_commits, recv_commits) =
            (sent_layout.commit.clone(), recv_layout.commit.clone());
        for range in sent_commits {
            tc_builder
                .commit_sent(&range)
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("commit sent: {e}"),
                })?;
        }
        for range in recv_commits {
            tc_builder
                .commit_recv(&range)
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("commit recv: {e}"),
                })?;
        }
        let transcript_commit = tc_builder.build().map_err(|e| Error::MpcTlsFailed {
            detail: format!("transcript commit config: {e}"),
        })?;

        let mut prove_config = ProveConfig::builder(&transcript);
        prove_config.server_identity();
        for range in &notary_sent_ranges {
            prove_config
                .reveal_sent(range)
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("reveal sent: {e}"),
                })?;
        }
        for range in &reveal_recv_ranges {
            prove_config
                .reveal_recv(range)
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("reveal recv: {e}"),
                })?;
        }
        prove_config.transcript_commit(transcript_commit.clone());

        let prover_output: ProverOutput = prover
            .prove(&prove_config.build().map_err(|e| Error::MpcTlsFailed {
                detail: format!("prove config: {e}"),
            })?)
            .await
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("prove: {e}"),
            })?;
        info!("MPC-TLS proof complete");
        on_progress(ProverStep::MpcProofFinalized);

        let tls_transcript = prover.tls_transcript().clone();
        let handshake = extract_handshake_data(&tls_transcript)?;

        let mut req_config = RequestConfig::builder();
        req_config
            .signature_alg(SignatureAlgId::SECP256K1ETH)
            .hash_alg(HashAlgId::KECCAK256)
            .transcript_commit(transcript_commit);
        let req_config = req_config.build().map_err(|e| Error::MpcTlsFailed {
            detail: format!("request config: {e}"),
        })?;

        let certs = tls_transcript
            .server_cert_chain()
            .ok_or_else(|| Error::MpcTlsFailed {
                detail: "server cert chain not available".into(),
            })?
            .to_vec();
        let sig = tls_transcript
            .server_signature()
            .ok_or_else(|| Error::MpcTlsFailed {
                detail: "server signature not available".into(),
            })?
            .clone();
        let binding = tls_transcript.certificate_binding().clone();

        let mut req_builder = Request::builder(&req_config);
        req_builder
            .server_name(ServerName::Dns(api_host.try_into().map_err(|e| {
                Error::MpcTlsFailed {
                    detail: format!("server name: {e}"),
                }
            })?))
            .handshake_data(HandshakeData {
                certs,
                sig,
                binding,
            })
            .transcript(transcript)
            .transcript_commitments(
                prover_output.transcript_secrets.clone(),
                prover_output.transcript_commitments,
            );
        // Taken before the secrets move into the request: the builder consumes
        // them and `Secrets` exposes no accessor, so this is the only point at
        // which a caller can still be handed what opens its own commitments.
        //
        // A secret of a kind this cannot open is refused rather than skipped:
        // dropping one would hand the caller fewer openings than it made
        // commitments, and it would find that out later, somewhere the reason
        // is no longer visible.
        let commitment_openings: Vec<CommitmentOpening> = prover_output
            .transcript_secrets
            .into_iter()
            .map(|secret| match secret {
                TranscriptSecret::Hash(hash) => Ok(CommitmentOpening {
                    direction: hash.direction,
                    ranges: hash.idx.into_inner(),
                    blinder: hash.blinder.as_bytes().to_vec(),
                }),
                other => Err(Error::MpcTlsFailed {
                    detail: format!(
                        "commitment secret of a kind this build cannot open: {other:?}"
                    ),
                }),
            })
            .collect::<Result<_>>()?;
        // The request itself goes nowhere: the notary answers a session with the
        // section 9.1 record and reads no attestation request. `build` is still
        // what produces `secrets`, so it stays.
        let (_att_request, secrets) = req_builder
            .build(&CryptoProvider::default())
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("attestation request: {e}"),
            })?;
        info!("Attestation request built");

        prover.close().await.map_err(|e| Error::MpcTlsFailed {
            detail: format!("prover close: {e}"),
        })?;
        handle.close();

        Ok((body, secrets, handshake, commitment_openings))
    };
    tokio::pin!(setup);

    // Race setup against the driver. The driver only finishes early when the
    // connection to the verifier died under the session — a protocol request
    // already submitted to it may then never resolve, so fail instead of
    // pending forever.
    let (body, secrets, handshake, commitment_openings) = tokio::select! {
        biased;
        res = &mut setup => res?,
        driver_res = driver_task.handle_mut() => {
            return Err(driver_finished_early(driver_res));
        }
    };

    let recovered_compat: Compat<T> = driver_task
        .into_inner()
        .await
        .map_err(|e| Error::MpcTlsFailed {
            detail: format!("driver task join: {e}"),
        })?
        .map_err(|e| Error::MpcTlsFailed {
            detail: format!("driver task: {e}"),
        })?;
    let recovered_io = recovered_compat.into_inner();

    Ok(ProverResult {
        response_body: body.to_vec(),
        secrets,
        handshake,
        commitment_openings,
        recovered_io,
    })
}

/// Run the MPC-TLS verifier (notary).
#[instrument(skip_all)]
pub async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<VerifierResult<T>> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let mut driver_task = AbortOnDrop::new(tokio::spawn(driver));

    let setup = async {
        let verifier = handle
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(root_store())
                    .build()
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("verifier config: {e}"),
                    })?,
            )
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("new verifier: {e}"),
            })?
            .commit()
            .await
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("verifier commit: {e}"),
            })?;

        let verifier = match verifier {
            VerifierCommitStart::Mpc(v) => {
                if v.config().max_sent_data() > MAX_SENT_DATA
                    || v.config().max_recv_data() > MAX_RECV_DATA
                {
                    v.reject(Some("data limits exceeded")).await.map_err(|e| {
                        Error::MpcTlsFailed {
                            detail: format!("reject: {e}"),
                        }
                    })?;
                    return Err(Error::MpcTlsFailed {
                        detail: "data limits exceeded".into(),
                    });
                }
                v.accept().await.map_err(|e| Error::MpcTlsFailed {
                    detail: format!("accept: {e}"),
                })?
            }
            _ => {
                return Err(Error::MpcTlsFailed {
                    detail: "expected MPC-TLS protocol".into(),
                });
            }
        };

        let verifier = verifier.run().await.map_err(|e| Error::MpcTlsFailed {
            detail: format!("run: {e}"),
        })?;

        let tls_transcript = verifier.tls_transcript().clone();

        let verifier = verifier.verify().await.map_err(|e| Error::MpcTlsFailed {
            detail: format!("verify: {e}"),
        })?;
        if !verifier.request().server_identity() {
            verifier
                .reject(Some("expecting server identity"))
                .await
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("reject: {e}"),
                })?;
            return Err(Error::MpcTlsFailed {
                detail: "no server identity".into(),
            });
        }

        let (output, verifier) =
            verifier.accept().await.map_err(|e| Error::MpcTlsFailed {
                detail: format!("accept verify: {e}"),
            })?;

        let VerifierOutput {
            server_name,
            transcript,
            transcript_commitments,
            ..
        } = output;
        let server_name = server_name.ok_or_else(|| Error::MpcTlsFailed {
            detail: "server name not revealed".into(),
        })?;
        let transcript = transcript.ok_or_else(|| Error::MpcTlsFailed {
            detail: "transcript not revealed".into(),
        })?;
        let ServerName::Dns(ref name) = server_name;
        info!("Verified server: {}", name.as_str());

        verifier.close().await.map_err(|e| Error::MpcTlsFailed {
            detail: format!("verifier close: {e}"),
        })?;
        handle.close();

        Ok((
            server_name,
            transcript,
            tls_transcript,
            transcript_commitments,
        ))
    };
    tokio::pin!(setup);

    // Race setup against the driver. The driver only finishes early when the
    // connection died under the session (e.g. a health probe that connected
    // and immediately closed) — a protocol request already submitted to it
    // may then never resolve, so fail instead of pending forever.
    let (server_name, transcript, tls_transcript, transcript_commitments) = tokio::select! {
        biased;
        res = &mut setup => res?,
        driver_res = driver_task.handle_mut() => {
            return Err(driver_finished_early(driver_res));
        }
    };

    let recovered_compat: Compat<T> = driver_task
        .into_inner()
        .await
        .map_err(|e| Error::MpcTlsFailed {
            detail: format!("driver task join: {e}"),
        })?
        .map_err(|e| Error::MpcTlsFailed {
            detail: format!("driver task: {e}"),
        })?;
    let recovered_io = recovered_compat.into_inner();

    Ok(VerifierResult {
        partial_transcript: transcript,
        server_name,
        tls_transcript,
        transcript_commitments,
        recovered_io,
    })
}
