//! MPC-TLS session setup and execution for both prover and verifier.

use http_body_util::BodyExt;
use hyper::{
    body::Bytes,
    StatusCode,
};
use hyper_util::rt::TokioIo;
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
        PartialTranscript,
        TlsTranscript,
        TranscriptCommitConfig,
        TranscriptCommitment,
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
    ceremony::{
        self,
        IdShape,
    },
    find_notary_reveal_ranges,
    find_presentation_commit_ranges,
    TlsHandshakeData,
};

use crate::{
    Error,
    Result,
};

use std::ops::Range;

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

/// Sub-steps within the MPC-TLS prover phase, reported via callback.
#[derive(Debug, Clone, Copy)]
pub enum ProverStep {
    /// MPC-TLS session established with notary.
    MpcSetupComplete,
    /// TLS handshake completed via MPC.
    TlsHandshakeComplete,
    /// Platform user data fetched over MPC-TLS.
    PlatformDataFetched,
    /// MPC proof finalized.
    MpcProofFinalized,
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

/// Result from the MPC-TLS prover.
pub struct ProverResult<T> {
    /// The HTTP response body from the platform API (decoded, headers stripped).
    pub response_body: Vec<u8>,
    /// Revealed recv segments — the exact bytes the prover disclosed to the notary.
    /// The notary hashes each segment as `double_hash_leaf("recv:", segment)` to
    /// build the `recv:` Merkle leaves of the EvmProof. One entry per revealed range.
    pub recv_segments: Vec<Vec<u8>>,
    /// The attestation request to send to the notary.
    pub request: Request,
    /// The TLS secrets for proof construction.
    pub secrets: Secrets,
    /// Extracted TLS handshake data.
    pub handshake: TlsHandshakeData,
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

/// The HTTPS request the prover performs over MPC-TLS.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequestSpec<'a> {
    /// API host (SNI and Host header), e.g. `"api.x.com"`.
    pub api_host: &'a str,
    /// Request path, e.g. `"/2/users/me"`.
    pub path: &'a str,
    /// HTTP method, e.g. `"GET"`.
    pub method: &'a str,
    /// Optional request body; when set, `Content-Type: application/json` is
    /// added.
    pub body: Option<&'a str>,
    /// Optional bearer token, sent as `Authorization: Bearer <token>`. `None`
    /// for unauthenticated endpoints (e.g. a public JWKS fetch).
    pub bearer_token: Option<&'a str>,
    /// User-Agent header value.
    pub user_agent: &'a str,
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
pub async fn prover<T, F>(
    socket: T,
    access_token: &str,
    params: &UserInfoParams<'_>,
    on_progress: F,
) -> Result<ProverResult<T>>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    F: Fn(ProverStep),
{
    let username_field = params.username_field;
    let id_field = params.id_field;
    prover_generic(
        socket,
        &HttpRequestSpec {
            api_host: params.api_host,
            path: params.user_info_path,
            method: "GET",
            body: None,
            bearer_token: Some(access_token),
            user_agent: params.user_agent,
        },
        // This flow predates the ceremony layouts and still selects the old
        // sparse ranges, which is why it cannot produce a ceremony attestation.
        // It goes at cutover; `RevealMode::Ceremony` is what replaces it.
        RevealMode::CallerSelected,
        |recv| {
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
            Ok(ranges)
        },
        on_progress,
    )
    .await
}

/// Run the MPC-TLS prover with arbitrary API parameters.
///
/// The reveal and commit ranges for one ceremony session, both directions.
fn ceremony_layouts(
    sent: &[u8],
    recv: &[u8],
    session: CeremonySession<'_>,
) -> Result<(ceremony::Layout, ceremony::Layout)> {
    let to_err = |e: ceremony::LayoutError| Error::MpcTlsFailed {
        detail: format!("ceremony layout: {e}"),
    };
    Ok(match session {
        CeremonySession::Token { secret_field } => (
            ceremony::token_request(sent, secret_field).map_err(to_err)?,
            ceremony::token_response(recv).map_err(to_err)?,
        ),
        CeremonySession::Identity {
            id_field,
            id_shape,
            handle_field,
        } => (
            ceremony::identity_request(sent).map_err(to_err)?,
            ceremony::identity_response(recv, id_field, id_shape, handle_field)
                .map_err(to_err)?,
        ),
    })
}

/// Which session of a ceremony this is, and therefore what it discloses.
///
/// The layouts come from `libid_transcript::ceremony`, where the commitments
/// are derived as the complement of the reveals so every direction tiles by
/// construction. A direction that does not tile is refused by the Platform
/// Verifier, so this is a correctness requirement rather than a disclosure
/// preference: choose the wrong ranges and no honest ceremony verifies.
#[derive(Clone, Copy, Debug)]
pub enum CeremonySession<'a> {
    /// X's `/2/oauth2/token`, or GitHub's token exchange when `secret_field`
    /// names the credential ordered last in its body.
    Token { secret_field: Option<&'a str> },
    /// X's `/2/users/me`, or GitHub's `/user`.
    Identity {
        id_field: &'a str,
        id_shape: IdShape,
        handle_field: &'a str,
    },
}

/// How a prover chooses its ranges.
#[derive(Clone, Copy, Debug)]
pub enum RevealMode<'a> {
    /// The ceremony layouts of the specification.
    Ceremony(CeremonySession<'a>),
    /// The caller selects the ranges itself: the request line and `Host`
    /// revealed and committed, the whole response committed, and the caller's
    /// closure choosing what of the response to reveal.
    ///
    /// This does NOT tile, so a ceremony attestation produced this way is
    /// rejected by the Platform Verifier. Two callers use it, and only one of
    /// them is waiting to be replaced:
    ///
    /// * the pre-ceremony X `/me` flow in [`prover`], which goes at cutover;
    /// * the notary's JWKS session, which is not a ceremony at all -- it reads
    ///   a public document, carries no credential, and reaches no Platform
    ///   Verifier. Nothing will replace it, so this variant outlives the
    ///   legacy flow that first needed it.
    CallerSelected,
}

/// The reveal and commit ranges for one ceremony session, both directions.
/// The `compute_reveal_ranges` closure receives the full `recv` transcript
/// data after the HTTP exchange completes and must return the byte ranges
/// within `recv` to selectively disclose. Each range becomes a separate
/// Merkle leaf in the notary's transcript tree. To reveal the entire
/// received transcript (as a JWKS-style notary requires), return
/// `vec![0..recv.len()]`.
///
/// Use [`libid_transcript::compute_field_reveal_range`] and friends inside
/// the closure to locate JSON field values in the response body.
#[instrument(skip_all, fields(api_host = request.api_host))]
pub async fn prover_generic<T, F, R>(
    socket: T,
    request: &HttpRequestSpec<'_>,
    reveal_mode: RevealMode<'_>,
    compute_reveal_ranges: R,
    on_progress: F,
) -> Result<ProverResult<T>>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    F: Fn(ProverStep),
    R: FnOnce(&[u8]) -> Result<Vec<Range<usize>>>,
{
    let api_host = request.api_host;

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

        let http_request = {
            let mut builder = hyper::Request::builder()
                .method(request.method)
                .uri(request.path)
                .header("Host", api_host)
                .header("Connection", "close")
                .header("Accept", "application/json")
                .header("User-Agent", request.user_agent);
            if let Some(token) = request.bearer_token {
                builder = builder.header("Authorization", format!("Bearer {}", token));
            }
            if request.body.is_some() {
                builder = builder.header("Content-Type", "application/json");
            }
            if let Some(post_body) = request.body {
                builder
                    .body(http_body_util::Full::new(Bytes::from(
                        post_body.to_string(),
                    )))
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("request build: {e}"),
                    })?
            } else {
                builder
                    .body(http_body_util::Full::new(Bytes::new()))
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("request build: {e}"),
                    })?
            }
        };

        info!("Sending {} {}", request.method, request.path);
        let response =
            sender
                .send_request(http_request)
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
        let (sent_layout, recv_layout) = match reveal_mode {
            RevealMode::Ceremony(session) => {
                let (s, r) = ceremony_layouts(sent, recv, session)?;
                (Some(s), Some(r))
            }
            RevealMode::CallerSelected => (None, None),
        };

        let reveal_recv_ranges = match &recv_layout {
            Some(l) => l.reveal.clone(),
            None => compute_reveal_ranges(recv)?,
        };

        // Save the revealed recv segments BEFORE the transcript is moved.
        // The notary hashes exactly these bytes into the `recv:` Merkle leaves, so
        // saving them here lets the ZK prover verify the full chain.
        let recv_segments: Vec<Vec<u8>> = reveal_recv_ranges
            .iter()
            .map(|r| recv[r.clone()].to_vec())
            .collect();

        let notary_sent_ranges = match &sent_layout {
            Some(l) => l.reveal.clone(),
            None => find_notary_reveal_ranges(sent),
        };

        let mut tc_builder = TranscriptCommitConfig::builder(&transcript);
        let (sent_commits, recv_commits) = match (&sent_layout, &recv_layout) {
            (Some(s), Some(r)) => (s.commit.clone(), r.commit.clone()),
            _ => (
                find_presentation_commit_ranges(sent),
                core::iter::once(0..recv.len()).collect(),
            ),
        };
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
                prover_output.transcript_secrets,
                prover_output.transcript_commitments,
            );
        let (att_request, secrets) = req_builder
            .build(&CryptoProvider::default())
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("attestation request: {e}"),
            })?;
        info!("Attestation request built");

        prover.close().await.map_err(|e| Error::MpcTlsFailed {
            detail: format!("prover close: {e}"),
        })?;
        handle.close();

        Ok((body, recv_segments, att_request, secrets, handshake))
    };
    tokio::pin!(setup);

    // Race setup against the driver. The driver only finishes early when the
    // connection to the verifier died under the session — a protocol request
    // already submitted to it may then never resolve, so fail instead of
    // pending forever.
    let (body, recv_segments, att_request, secrets, handshake) = tokio::select! {
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
        recv_segments,
        request: att_request,
        secrets,
        handshake,
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
