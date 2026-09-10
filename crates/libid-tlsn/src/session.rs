//! MPC-TLS session setup and execution for both prover and verifier.

use http_body_util::BodyExt;
use hyper::{
    body::Bytes,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use libid_transcript::ceremony::Layout;
use std::{
    future::IntoFuture,
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};
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
        tls_commit::{
            mpc::MpcTlsConfig,
            proxy::ProxyTlsConfig,
        },
        verifier::VerifierConfig,
    },
    connection::{
        DnsName,
        HandshakeData,
        ServerName,
    },
    hash::HashAlgId,
    prover::ProverOutput,
    transcript::{
        ContentType,
        Direction,
        PartialTranscript,
        Record,
        TlsTranscript,
        Transcript,
        TranscriptCommitConfig,
        TranscriptCommitment,
        TranscriptCommitmentKind,
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

/// The application data one direction of a finished session actually carried.
///
/// The same sum the verifier makes to decide a transcript's true length, taken
/// here so a commitment can be measured against it before anything allocates
/// over it.
fn application_data_len(records: &[Record]) -> usize {
    records
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| record.ciphertext.len())
        .sum()
}

/// The first committed range that runs past the direction it names, if any.
///
/// A prover states its commitments as bare offsets, and NOTHING upstream
/// bounds them against the session: `TranscriptCommitConfigBuilder` refuses an
/// out-of-range commitment, but `ProveRequest` derives its deserializer with no
/// validation, so a prover that writes its own wire bytes never runs that
/// check. On this side each committed range is allocated over and then used to
/// index the transcript's plaintext, so an oversized range is an allocation the
/// session never justified and an out-of-range one indexes past the end.
///
/// Separate from the session so it can be tested without one: the shapes worth
/// testing are all a prover's arithmetic, not a notarization.
/// Each commitment is given as its direction and the end of the range it
/// covers, which is the only part of it that can run past the session; an
/// empty range set has no end and cannot.
fn commitment_past_the_session(
    commitments: impl IntoIterator<Item = (Direction, Option<usize>)>,
    sent_len: usize,
    recv_len: usize,
) -> Option<(Direction, usize, usize)> {
    commitments.into_iter().find_map(|(direction, end)| {
        let len = match direction {
            Direction::Sent => sent_len,
            Direction::Received => recv_len,
        };
        end.filter(|end| *end > len)
            .map(|end| (direction, end, len))
    })
}

/// What this session commits to, and under which hash.
///
/// Split out of `prover_generic` so the algorithm is assertable without an
/// MPC session: the config is the only place the choice is made, and it is
/// made here rather than by a caller, because `select_layout` hands back
/// ranges and no algorithm.
fn transcript_commit_config(
    transcript: &Transcript,
    sent: &[std::ops::Range<usize>],
    recv: &[std::ops::Range<usize>],
) -> Result<TranscriptCommitConfig> {
    let mut builder = TranscriptCommitConfig::builder(transcript);
    // REQ-COMMON-38. The notarization library defaults to BLAKE3 and the
    // Proving Circuit computes SHA-256, so a prover left on that default
    // produces commitments the circuit cannot open -- and which
    // `AttestedData::from_observed` refuses, after a whole MPC-TLS session has
    // been paid for. It is set here because `select_layout` hands back ranges
    // and no algorithm, so no caller can correct it.
    builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    for range in sent {
        builder
            .commit_sent(range)
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("commit sent: {e}"),
            })?;
    }
    for range in recv {
        builder
            .commit_recv(range)
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("commit recv: {e}"),
            })?;
    }
    builder.build().map_err(|e| Error::MpcTlsFailed {
        detail: format!("transcript commit config: {e}"),
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
    /// One opening per commitment this session made, in no particular order:
    /// tlsn hands the commitments back from a set, so a caller finds its
    /// opening by the `ranges` it covers rather than by position. Empty when
    /// the session committed nothing.
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

/// Rewrite the request's URI to origin-form before it goes on the wire.
///
/// `hyper::client::conn::http1` writes the request-target exactly as the
/// `Uri` displays (`Client::encode` in `proto/h1/role.rs`); only hyper-util's
/// pooled client rewrites it, and [`prover_generic`] drives a raw connection.
/// A caller hands us an absolute URI because that is where the host comes
/// from, so left alone the request line would read
/// `GET https://www.googleapis.com/oauth2/v3/certs HTTP/1.1` -- valid HTTP,
/// but not the origin-form line the Platform Verifiers and `GoogleJwtRoots`
/// pin, so the session would be refused on chain.
///
/// Only the URI changes: the `Host` header the caller set stays as it is.
fn origin_form<B>(request: &mut hyper::Request<B>) -> Result<()> {
    let target = match request.uri().path_and_query() {
        Some(path) => {
            let mut parts = hyper::http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            hyper::Uri::from_parts(parts).map_err(|e| Error::MpcTlsFailed {
                detail: format!("origin-form request-target: {e}"),
            })?
        }
        None => hyper::Uri::default(),
    };
    *request.uri_mut() = target;
    Ok(())
}

/// Which commitment protocol a session runs.
///
/// Not public, and deliberately: a caller picks a transport by calling
/// [`prover_generic`] or [`prover_proxy`], which is one decision made at one
/// place rather than a parameter that can be threaded through three layers and
/// arrive wrong.
#[derive(Clone, Copy, Debug)]
enum Transport {
    /// MPC-TLS. This side opens the connection to the server; the notary takes
    /// part in encrypting it and never sees the plaintext.
    Mpc,
    /// Proxy-TLS. The NOTARY opens the connection to the server and this side
    /// reaches it through the session mux. The notary still never sees the
    /// plaintext -- it forwards ciphertext -- but the egress is its.
    Proxy,
}

/// What this side authenticates the server against, on either transport.
///
/// One function because both transports need the identical value and a second
/// spelling of it is a second thing that can disagree about which roots a
/// session trusts.
fn tls_client_config(api_host: &str) -> Result<TlsClientConfig> {
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
        })
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
/// Each revealed range is carried in the attested record with the offsets it
/// sat at, and each hidden run as one commitment; `libid_transcript::ceremony`
/// is what chooses them for a launch profile.
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
///
/// The request's URI must be absolute -- the host names the server -- but the
/// wire carries the request-target in origin-form (`GET /path?query HTTP/1.1`),
/// which is the line every verifier pins. See [`origin_form`].
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
    prover_with(Transport::Mpc, socket, request, select_layout, on_progress).await
}

/// The same session, reached through the notary rather than opened here.
///
/// Everything a caller sees is identical to [`prover_generic`] -- the same
/// arguments, the same layout callback, the same [`ProverResult`], and the
/// same attested record for the Platform Verifier to read. Only the way the
/// server is reached differs: the notary opens the connection and forwards
/// ciphertext, so `socket` carries the platform's traffic as well as the
/// protocol's, and this process makes no outbound connection of its own.
///
/// That is the whole reason to choose it. A prover that cannot reach the
/// platform directly -- a browser, or a service whose egress is closed -- can
/// still run the session, and a deployment that would rather not egress to
/// every platform it supports need not.
///
/// It is NOT more or less private. The notary sees the same ciphertext either
/// way and the plaintext neither way; what moves is which side dials.
#[instrument(skip_all)]
pub async fn prover_proxy<T, S, F>(
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
    prover_with(
        Transport::Proxy,
        socket,
        request,
        select_layout,
        on_progress,
    )
    .await
}

/// Both provers, which are one prover with one branch.
///
/// The two public entry points above exist so a caller states its transport by
/// choosing a function rather than passing a value; everything they share is
/// here, once, because the parts that are not the connection -- the HTTP
/// exchange, the disclosure the prover chooses, the commitments, the attested
/// record -- are the parts a verifier reads, and two copies of them is two
/// copies that can disagree about what a session proves.
async fn prover_with<T, S, F>(
    transport: Transport,
    socket: T,
    mut request: hyper::Request<http_body_util::Full<Bytes>>,
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
    origin_form(&mut request)?;

    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let mut driver_task = AbortOnDrop::new(tokio::spawn(driver));

    // Set once the session has run. Before that, the driver finishing means the
    // connection died under the session; after, it means the peer closed the
    // mux, which is how a session ends.
    let established = AtomicBool::new(false);
    let established = &established;
    let setup = async {
        // The commitment protocol, and the ONLY place the two transports
        // differ. Everything after it is the same work on the same types: a
        // connected prover's future resolves to `Prover<state::Committed>`
        // whichever way the connection was made, so the HTTP exchange, the
        // layout the prover chooses, the commitments and the attested record
        // are written once and mean the same thing in both.
        let (tls, prover_task) = match transport {
            // The prover opens the connection to the server and the notary
            // takes part in encrypting it. Egress to the platform is this
            // side's.
            Transport::Mpc => {
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
                let tcp =
                    tokio::net::TcpStream::connect(format!("{}:443", api_host)).await?;
                let (tls, prover) = prover
                    .connect(tls_client_config(api_host)?, tcp.compat())
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("connect: {e}"),
                    })?;
                (tls, AbortOnDrop::new(tokio::spawn(prover.into_future())))
            }
            // The NOTARY opens the connection to the server, and this side
            // reaches it through the session mux. There is no socket to pass
            // and no egress from here -- which is the whole reason a caller
            // that cannot reach the platform itself, or must not, uses this.
            Transport::Proxy => {
                info!("Setting up Proxy-TLS");
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
                        ProxyTlsConfig::builder()
                            .server_name(DnsName::try_from(api_host).map_err(|e| {
                                Error::MpcTlsFailed {
                                    detail: format!("server name: {e}"),
                                }
                            })?)
                            .build()
                            .map_err(|e| Error::MpcTlsFailed {
                                detail: format!("proxy tls config: {e}"),
                            })?,
                    )
                    .await
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("commit: {e}"),
                    })?;
                info!("Proxy-TLS setup complete");
                on_progress(ProverStep::MpcSetupComplete);

                info!("Reaching {} through the notary", api_host);
                let (tls, prover) = prover
                    .connect(tls_client_config(api_host)?)
                    .map_err(|e| Error::MpcTlsFailed {
                        detail: format!("connect: {e}"),
                    })?;
                (tls, AbortOnDrop::new(tokio::spawn(prover.into_future())))
            }
        };
        info!("TLS handshake complete");
        on_progress(ProverStep::TlsHandshakeComplete);

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

        let transcript_commit = transcript_commit_config(
            &transcript,
            &sent_layout.commit,
            &recv_layout.commit,
        )?;

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
        established.store(true, Ordering::Release);
        on_progress(ProverStep::MpcProofFinalized);

        let tls_transcript = prover.tls_transcript().clone();

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
        // attested-data record and reads no attestation request. `build` is still
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

        Ok((body, secrets, commitment_openings))
    };
    tokio::pin!(setup);

    // Race setup against the driver. The driver only finishes early when the
    // connection to the verifier died under the session — a protocol request
    // already submitted to it may then never resolve, so fail instead of
    // pending forever.
    let mut finished_driver = None;
    let (body, secrets, commitment_openings) = tokio::select! {
        biased;
        res = &mut setup => res?,
        driver_res = driver_task.handle_mut() => {
            if !established.load(Ordering::Acquire) {
                return Err(driver_finished_early(driver_res));
            }
            // The peer closed the mux as its last act while this side was
            // still finishing. Let setup complete and keep the driver's
            // result: a finished handle cannot be polled a second time. Not a
            // `select!` precondition, which is evaluated once, on entry.
            finished_driver = Some(driver_res);
            (&mut setup).await?
        }
    };

    let driver_res = match finished_driver {
        Some(res) => res,
        None => driver_task.into_inner().await,
    };
    let recovered_compat: Compat<T> = driver_res
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

    // Set once the session has run. Before that, the driver finishing means the
    // connection died under the session; after, it means the peer closed the
    // mux, which is how a session ends.
    let established = AtomicBool::new(false);
    let established = &established;
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
        established.store(true, Ordering::Release);

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

        // Refuse a commitment this session cannot contain, BEFORE `accept`
        // walks it. `accept` allocates in proportion to every committed range
        // and then indexes the plaintext with it, so a range the prover made
        // up is either an allocation nothing bounds or an index past the end.
        // Checked here rather than upstream because this is the last point
        // that holds both the request and the transcript it describes.
        let overrun = verifier.request().transcript_commit().and_then(|commit| {
            commitment_past_the_session(
                commit
                    .iter_hash()
                    .map(|(direction, idx, _)| (*direction, idx.end())),
                application_data_len(tls_transcript.sent()),
                application_data_len(tls_transcript.recv()),
            )
        });
        if let Some((direction, end, len)) = overrun {
            verifier
                .reject(Some("commitment range out of bounds"))
                .await
                .map_err(|e| Error::MpcTlsFailed {
                    detail: format!("reject: {e}"),
                })?;
            return Err(Error::MpcTlsFailed {
                detail: format!(
                    "a {direction} commitment ends at {end}, past the {len} bytes \
                     this session carried"
                ),
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
    let mut finished_driver = None;
    let (server_name, transcript, tls_transcript, transcript_commitments) = tokio::select! {
        biased;
        res = &mut setup => res?,
        driver_res = driver_task.handle_mut() => {
            if !established.load(Ordering::Acquire) {
                return Err(driver_finished_early(driver_res));
            }
            // The peer closed the mux as its last act while this side was
            // still finishing. Let setup complete and keep the driver's
            // result: a finished handle cannot be polled a second time. Not a
            // `select!` precondition, which is evaluated once, on entry.
            finished_driver = Some(driver_res);
            (&mut setup).await?
        }
    };

    let driver_res = match finished_driver {
        Some(res) => res,
        None => driver_task.into_inner().await,
    };
    let recovered_compat: Compat<T> = driver_res
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str) -> hyper::Request<()> {
        hyper::Request::builder()
            .uri(uri)
            .header("Host", "www.googleapis.com")
            .body(())
            .expect("valid request")
    }

    /// REQ-COMMON-38: launch profiles pin SHA-256, because the Proving
    /// Circuit computes SHA-256 and cannot open a commitment made under
    /// anything else.
    ///
    /// This is asserted on the CONFIG rather than on a notarized session,
    /// because the algorithm is chosen here and nowhere else -- `select_layout`
    /// hands back ranges, so no caller can correct it. The unit tests that
    /// cover the record synthesize their own commitments and hard-code
    /// SHA-256, so they assert on an algorithm no code path in this crate
    /// produces; this is the gap that leaves.
    #[test]
    fn every_commitment_this_prover_configures_is_sha256() {
        let transcript =
            Transcript::new(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\nx");
        // Two ranges per direction: the algorithm is per commitment, so one
        // range could not tell a default applied once from one applied to each.
        let config =
            transcript_commit_config(&transcript, &[0..4, 6..10], &[0..4, 6..10])
                .expect("the ranges are inside the transcript");

        let algs: Vec<_> = config.iter_hash().map(|(_, alg)| *alg).collect();
        assert_eq!(algs.len(), 4, "two commitments per direction");
        for alg in algs {
            assert_eq!(
                alg,
                HashAlgId::SHA256,
                "a commitment under {alg:?} is one the circuit cannot open, and \
                 one `AttestedData::from_observed` refuses (REQ-COMMON-38)"
            );
        }
    }

    /// A record as a finished session holds it, for the length sum below.
    fn record(typ: ContentType, len: usize) -> Record {
        Record {
            seq: 0,
            typ,
            plaintext: None,
            explicit_nonce: Vec::new(),
            ciphertext: vec![0; len],
            tag: None,
        }
    }

    #[test]
    fn the_session_length_counts_only_its_application_data() {
        // A transcript's offsets are into its application data. Handshake and
        // alert records ride the same wire and belong to no direction's
        // offsets, so counting them would leave room for a commitment the
        // transcript has no bytes for.
        let records = [
            record(ContentType::Handshake, 100),
            record(ContentType::ApplicationData, 40),
            record(ContentType::Alert, 7),
            record(ContentType::ApplicationData, 2),
        ];
        assert_eq!(application_data_len(&records), 42);
    }

    #[test]
    fn a_commitment_past_the_session_is_refused() {
        // The shape a prover writes by hand. `TranscriptCommitConfigBuilder`
        // refuses it, and a prover composing its own wire bytes never calls
        // that builder -- `ProveRequest` deserializes with no validation of
        // its own, so this is the only place the offsets are met.
        assert_eq!(
            commitment_past_the_session([(Direction::Sent, Some(1 << 40))], 4096, 4096),
            Some((Direction::Sent, 1 << 40, 4096)),
            "an enormous range is an allocation the session never justified"
        );
        assert_eq!(
            commitment_past_the_session([(Direction::Received, Some(4097))], 4096, 4096),
            Some((Direction::Received, 4097, 4096)),
            "one byte past the end still indexes past the plaintext"
        );
    }

    #[test]
    fn a_commitment_the_session_carried_is_allowed() {
        // Each direction is measured against its OWN length, so a range that
        // would overrun the other one is still one this session can open.
        assert_eq!(
            commitment_past_the_session(
                [
                    (Direction::Sent, Some(4096)),
                    (Direction::Received, Some(30_000)),
                    (Direction::Sent, None),
                ],
                4096,
                32_768,
            ),
            None
        );
    }

    #[test]
    fn origin_form_keeps_path_and_query() {
        let mut request = request("https://www.googleapis.com/p?q=1");
        origin_form(&mut request).expect("origin-form");
        assert_eq!(request.uri().to_string(), "/p?q=1");
    }

    #[test]
    fn origin_form_keeps_a_bare_path() {
        let mut request = request("https://www.googleapis.com/p");
        origin_form(&mut request).expect("origin-form");
        assert_eq!(request.uri().to_string(), "/p");
    }

    #[test]
    fn origin_form_leaves_the_host_header_alone() {
        let mut request = request("https://www.googleapis.com/oauth2/v3/certs");
        origin_form(&mut request).expect("origin-form");
        assert_eq!(request.uri().host(), None);
        assert_eq!(
            request.headers().get("Host").map(|v| v.as_bytes()),
            Some(&b"www.googleapis.com"[..])
        );
    }
}
