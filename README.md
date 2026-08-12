# libid-rs

Shared Rust crates for MPC-TLS / zkTLS infrastructure: run TLSNotary-style
notarization sessions, carve selective-disclosure ranges out of TLS
transcripts, build the Merkle/EIP-191 proof material, and produce the exact
digests the libID on-chain verifiers check.

## Crates

| Crate | crates.io | What it is |
| --- | --- | --- |
| `libid-crypto` | yes | Contract-agnostic primitives: keccak256, EIP-191 sign/recover (27/28 `v`, low-s), OpenZeppelin-compatible sorted-pair keccak Merkle tree (root, inclusion proofs, verify, double-hashed prefixed leaves), Ethereum address and hex-key helpers. Minimal deps: `k256`, `tiny-keccak`, `hex`. |
| `libid-transcript` | yes | The tlsn-free half of the MPC-TLS toolkit. HTTP/JSON transcript range math for selective disclosure (header/body/chunked decoding, JSON field and `"key":"value"` snippet ranges, bare-number id snippets, anchored lookups, notary reveal ranges); the length-prefixed JSON wire protocol notary and prover speak after MPC-TLS closes; the `EvmProof` / `NotaryResponse` / `TlsHandshakeData` types. |
| `libid-attestations` | yes | Contract-ABI-shaped digest builders, byte-pinned against the Solidity verifiers: chain-bound notary digest, JWKS-rotation notary digest (legacy 6-slot), backend digest, identity hash, and the XZkVerifier token/me attestation digests with their op-tags. |
| `libid-signer` | yes | `ManagedSigner` — one signing identity over a local hex key or an AWS KMS key: EIP-191 claim signing (byte-compatible with `libid_crypto::sign_eth_claim`), bare prehash signing (the tlsn `Secp256k1Eth` format), alloy transaction wallets, public-key accessors, and `SignerSource::from_spec` shape-classified key-spec parsing (64-hex → local key, anything else → KMS). |
| `libid-tlsn` | **no — git only** | The MPC-TLS session driver over the upstream `tlsn` crate: `prover` / `prover_generic` / `verifier` over any async socket, TLS 1.2 handshake-data extraction, WebPKI root store. |

## The tlsn git-dep caveat

`libid-tlsn` depends on `tlsn` pinned to a git revision
(`tlsnotary/tlsn @ 040c6881`); the TLSNotary project publishes nothing to
crates.io, and cargo refuses to publish crates with git dependencies. Until
upstream cuts a matching release, consume it as a git dependency:

```toml
[dependencies]
libid-tlsn = { git = "https://github.com/libid-org/libid-rs", tag = "v0.1.0" }
```

The crate split exists precisely so this caveat stays contained: everything
that does not need `tlsn` types — range math, wire protocol, proof types,
digests, signing — is published normally and never drags the git pin into
your lockfile.

## Feature flags

* `libid-transcript/ts` — derives `ts_rs::TS` on `EvmProof` and
  `NotaryResponse` for TypeScript bindings generation. Off by default so
  production builds don't carry `ts-rs`.
* `libid-tlsn` and everything else: no features.

## Usage sketch

A notary (verifier side) accepts a socket, runs the MPC-TLS verifier, then
answers over the same socket:

```rust,ignore
let result = libid_tlsn::verifier(socket).await?;
// inspect result.partial_transcript / result.tls_transcript, build an
// EvmProof with libid_crypto merkle + libid_attestations digests, sign it
// with libid_signer::ManagedSigner, then:
libid_transcript::write_msg(&mut result.recovered_io, &response).await?;
```

A prover connects to a notary and fetches an authenticated endpoint,
revealing only the chosen JSON snippets:

```rust,ignore
let out = libid_tlsn::prover(
    socket,
    access_token,
    &libid_tlsn::UserInfoParams {
        api_host: "api.x.com",
        user_info_path: "/2/users/me",
        username_field: "username",
        id_field: Some(("id", true)),
        user_agent: "my-prover/1.0",
    },
    |step| tracing::info!(?step),
)
.await?;
```

Unauthenticated full-reveal flows (e.g. notarizing a JWKS endpoint) use
`prover_generic` with `bearer_token: None` and a closure returning
`vec![0..recv.len()]`.

## Versioning and releases

All crates share the single `[workspace.package]` version. A release is cut
by publishing a GitHub Release tagged `v<version>`; CI verifies the tag
matches the manifests, then publishes the four publishable crates in
dependency order (already-published versions are skipped, so a re-run is
safe). `libid-tlsn` ships via the same git tag instead.

## License

MIT OR Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
