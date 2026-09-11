# libid-rs

Shared Rust crates for MPC-TLS / zkTLS infrastructure: run TLSNotary-style
notarization sessions, carve selective-disclosure ranges out of TLS
transcripts, sign the EIP-191 material, and produce the exact attested-data
record the libID on-chain verifiers check.

## Crates

| Crate | crates.io | What it is |
| --- | --- | --- |
| `libid-crypto` | yes | Contract-agnostic primitives: keccak256, EIP-191 sign/recover (27/28 `v`, low-s) — the pair a notary signature is made and checked with — plus address derivation and hex-key parsing. Minimal deps: `k256`, `tiny-keccak`, `hex`. |
| `libid-transcript` | yes | The tlsn-free half of the MPC-TLS toolkit. HTTP/JSON transcript range math for selective disclosure (header/body/chunked decoding, `"key":"value"` and bare-number member ranges); the per-session ceremony reveal layouts, built from the profile table generated in libid-contracts; the length-prefixed JSON wire protocol notary and prover speak after MPC-TLS closes; the `AttestationWire` type. |
| `libid-ceremony` | yes | The attested-data record a notary signs: the types a Platform Profile pins, their big-endian fixed-width encoder, and the keccak256 over it that is the only preimage a notary signs. Also the GitHub Token Service request and response records with the bounds a served call must satisfy. |
| `libid-signer` | yes | `ManagedSigner` — one signing identity over a local hex key or an AWS KMS key: EIP-191 claim signing (byte-compatible with `libid_crypto::sign_eth_claim`), bare prehash signing (the tlsn `Secp256k1Eth` format), alloy transaction wallets, public-key accessors, and `SignerSource::from_spec` shape-classified key-spec parsing (64-hex → local key, anything else → KMS). |
| `libid-tlsn` | **no — git only** | The MPC-TLS session driver over the upstream `tlsn` crate: `prover_generic` and `verifier` over any async socket, the attested-data record built from what a session was observed to be, WebPKI root store. |

## The tlsn git-dep caveat

`libid-tlsn` depends on the `tlsn` `v0.1.0-alpha.15` git tag; the TLSNotary
project publishes no `tlsn` crate to crates.io, and cargo refuses to publish
crates with git dependencies. Consume it as a git dependency:

```toml
[dependencies]
libid-tlsn = { git = "https://github.com/libid-org/libid-rs", tag = "v0.4.0" }
```

The crate split exists precisely so this caveat stays contained: everything
that does not need `tlsn` types — range math, reveal layouts, the attested-data
record, wire protocol, signing — is published normally and never drags the git
pin into your lockfile.

## Usage sketch

A notary (verifier side) accepts a socket, runs the MPC-TLS verifier, then
answers over the same socket:

```rust,ignore
let result = libid_tlsn::verifier(socket).await?;
// describe the session as a libid_tlsn::attest::ObservedSession and build
// the record with AttestedData::from_observed,
// sign its digest with libid_signer::ManagedSigner, then:
libid_transcript::write_msg(&mut result.recovered_io, &response).await?;
```

A prover connects to a notary, sends one request inside MPC-TLS, and decides
what of the exchange is revealed and what is committed. For a launch profile
that decision is `libid_transcript::ceremony`'s, built from the profile table
`libid-contracts` generates, so the prover and the on-chain verifier read one
definition:

```rust,ignore
use libid_tlsn::{Bytes, HttpBody, HttpRequest};
use libid_transcript::ceremony::{profiles, Layout};

let x = profiles::X.identity.expect("x notarizes an identity session");
let request = HttpRequest::builder()
    .method(x.session.method)
    .uri(format!("https://{}{}", x.session.authority, x.session.path))
    .header("authorization", format!("Bearer {access_token}"))
    .header("accept", "application/json")
    .header("host", x.session.authority)
    .header("connection", "close")
    .body(HttpBody::new(Bytes::new()))?;

let out = libid_tlsn::prover_generic(
    socket,
    request,
    |sent, recv| {
        let layouts = Layout::identity_request(sent)
            .and_then(|s| Layout::identity_response(recv, &x).map(|r| (s, r)));
        layouts.map_err(|e| libid_tlsn::Error::MpcTlsFailed { detail: e.to_string() })
    },
    |step| tracing::info!(?step),
)
.await?;
// out.response_body, out.secrets, out.commitment_openings, out.recovered_io
```

The URI is absolute because the host names the server; the wire carries the
origin-form request line the verifiers pin. A session that reads a public
document and reveals all of it -- notarizing a JWKS endpoint --
states its own layouts, revealing the whole of each direction.

## Versioning and releases

All crates share the single `[workspace.package]` version. A release is cut
by publishing a GitHub Release tagged `v<version>`; CI verifies the tag
matches the manifests, then publishes the four publishable crates in
dependency order (already-published versions are skipped, so a re-run is
safe). `libid-tlsn` ships via the same git tag instead.

## License

MIT OR Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
