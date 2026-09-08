//! Choosing what a notarized session reveals.
//!
//! The Platform Verifier checks that the revealed ranges and the commitments
//! TILE the transcript: every byte accounted for, no gap and no overlap. A gap
//! is where a prover hides bytes, so a session that leaves one is refused --
//! which means the selection here is not a disclosure preference, it is a
//! correctness requirement. Choose the wrong ranges and no honest ceremony
//! verifies at all.
//!
//! Every layout below therefore names only what it REVEALS, and the commitments
//! are derived as the complement. Tiling then holds by construction rather than
//! by inspection.
//!
//! Nothing here is applied on anyone's behalf. A prover notarizing a ceremony
//! session calls these and hands the result to `prover_generic`; a prover doing
//! something else states its own. In Rust that prover will be the GitHub
//! Token-Exchange Service, for the token session. The other three sessions are
//! the browser's.

use std::ops::Range;

use crate::ranges::{
    compute_field_snippet_range,
    compute_id_snippet_range,
    JsonMember,
};

/// What one direction of one session discloses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Ascending, non-overlapping.
    pub reveal: Vec<Range<usize>>,
    /// The complement of `reveal` over the whole direction.
    pub commit: Vec<Range<usize>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LayoutError {
    #[error("the request has no `{0}` header, so the layout has nothing to anchor on")]
    MissingHeader(&'static str),
    #[error("the response carries no `{0}` field where the profile expects one")]
    MissingField(String),
    #[error("the transcript has no head boundary, so its body cannot be located")]
    NoHeadBoundary,
    #[error("the credential to commit was not found in the request body")]
    MissingCredential,
}

/// The bytes of `[0, len)` that `reveal` does not cover.
///
/// Deriving the commitments this way is what makes every layout tile. The
/// alternative -- listing both and hoping they agree -- is the mistake the
/// verifier exists to catch.
fn complement(reveal: &[Range<usize>], len: usize) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    for r in reveal {
        if r.start > at {
            out.push(at..r.start);
        }
        at = r.end;
    }
    if at < len {
        out.push(at..len);
    }
    out
}

/// The ceremony profiles, and the types a layout is built from.
///
/// Re-exported rather than restated. `libid-profiles` is generated in
/// libid-contracts from `solidity/contracts/ceremony/profiles.json` -- the same
/// file `CeremonyProfile.sol` is generated from -- so what a prover reveals and
/// what a Platform Verifier compares it against come from one place. A table
/// written again here would be a second copy of values whose whole problem is
/// that copies drift in silence.
///
/// [`IdShape`] used to be declared here. It said the same thing the generated
/// one says, and two spellings of one profile fact is the drift this crate now
/// takes the table to avoid.
pub use libid_profiles::{
    self as profiles,
    IdShape,
    IdentitySession,
    Profile,
    TokenSession,
};

impl Layout {
    /// A layout that reveals these ranges of a direction `len` bytes long, and
    /// commits everything they leave.
    ///
    /// The one door into a tiling `Layout`, and the reason every constructor below
    /// tiles by construction rather than by inspection: no constructor states
    /// `commit`, so no constructor's list can disagree with the reveals it was
    /// supposed to complement. `layout` -- a lowercase homonym of the type it
    /// built, in a module about layouts -- said none of that.
    ///
    /// `complement` walks the reveals once, taking each as starting where the last
    /// one ended, so unsorted input reads as overlap and yields a complement that
    /// tiles nothing -- which the Platform Verifier rejects and nothing here would
    /// catch. Sorting is done once, here, so no caller has to remember: the
    /// layouts that build in order are unaffected, and
    /// [`Layout::identity_response`], whose two members arrive in whatever order
    /// the platform serialized them, carries no sort of its own. Overlapping input
    /// is a caller bug that sorting cannot repair, and the debug assertion is what
    /// says so.
    ///
    /// Private, and `Layout`'s fields stay public beside it. Callers outside this
    /// module state layouts this module does not know -- `libid-tlsn`'s legacy
    /// prover builds two whose ranges deliberately do not tile -- so tiling is a
    /// property of these constructors and not of the type. A public constructor
    /// advertising a guarantee the type does not enforce would be worse than no
    /// public constructor at all.
    ///
    /// It takes an iterator rather than a `Vec` so that a one-range layout is
    /// spelled `core::iter::once(a..b)`. Both `vec![a..b]` and `[a..b]` trip
    /// `clippy::single_range_in_vec_init`, a lint that exists to catch `vec![0; n]`
    /// typos and cannot tell this apart from one; the iterator form says what is
    /// meant without a named helper standing in for it.
    fn revealing(reveal: impl IntoIterator<Item = Range<usize>>, len: usize) -> Self {
        let mut reveal: Vec<Range<usize>> = reveal.into_iter().collect();
        reveal.sort_by_key(|r| r.start);
        debug_assert!(
            reveal.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "reveal ranges overlap: {reveal:?}"
        );
        let commit = complement(&reveal, len);
        Layout { reveal, commit }
    }

    /// The token request of `x/v1`, or the token exchange of `github/v1`.
    ///
    /// X reveals the request whole: it authenticates with a public client, so the
    /// request carries nothing secret and the head boundary stays visible, which is
    /// how the verifier locates the body at all. GitHub commits its `client_secret`
    /// alone -- ordered last in the body, so the revealed run is a prefix and the
    /// commitment reaches the transcript end.
    pub fn token_request(
        sent: &[u8],
        session: &TokenSession,
    ) -> Result<Self, LayoutError> {
        let Some(field) = session.secret_field else {
            return Ok(Self::revealing(core::iter::once(0..sent.len()), sent.len()));
        };

        // `&client_secret=` begins the committed tail. The profile orders it last
        // under REQ-COMMON-22 precisely so this is a suffix and not a hole.
        let needle = format!("&{field}=");
        let start = sent
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())
            .ok_or(LayoutError::MissingCredential)?;
        Ok(Self::revealing(core::iter::once(0..start), sent.len()))
    }

    /// The token response: the `"access_token":"` delimiter and its closing quote
    /// are revealed, and everything else -- the bearer included -- is committed.
    ///
    /// Those two anchors are what identify the committed bearer. Without them the
    /// committed range is indistinguishable from a `refresh_token` value, or any
    /// other substring the prover chose to commit (REQ-PLAT-57, REQ-PLAT-58).
    pub fn token_response(recv: &[u8]) -> Result<Self, LayoutError> {
        // Named once, and a constant rather than a parameter. `access_token` is
        // RFC 6749 section 5.1, not a platform's choice -- which is why the
        // contract pins `ACCESS_TOKEN_PREFIX` on `TlsNotaryVerifierBase`, shared by
        // every profile, while the things that ARE platform choices are per-profile
        // virtuals there and parameters here: the committed body credential of
        // `Layout::token_request`, the field names of
        // `Layout::identity_response`.
        const FIELD: &str = "access_token";
        let missing = || LayoutError::MissingField(FIELD.into());

        // Through the shared reader rather than a scan of its own. That one locates
        // the response BODY, so a header carrying this delimiter cannot answer
        // first, and it refuses a member that chunk framing runs through -- which
        // this direction cares about most, because the framing would land inside
        // the committed bearer and the circuit would open a value the token service
        // never returned.
        let found = JsonMember::in_response(recv, FIELD).ok_or_else(missing)?;

        // Reveal the two delimiters and let the complement commit the bearer
        // between them. Both boundaries come from the scan that found the member,
        // so nothing here restates `"access_token":"` to recompute one.
        //
        // An empty bearer is refused: it would leave the two reveals adjacent and
        // commit nothing, and a response direction with no commitment is one the
        // framing check on chain finds no bearer in.
        if found.value.is_empty() {
            return Err(missing());
        }

        Ok(Self::revealing(
            [
                found.member.start..found.value.start,
                found.value.end..found.member.end,
            ],
            recv.len(),
        ))
    }

    /// The identity request: every byte revealed except the bearer value, which is
    /// committed.
    ///
    /// The two revealed runs plus the committed one account for the request exactly,
    /// which is what REQ-COMMON-35 demands and what leaves the committed range as
    /// the only region the verifier cannot read.
    pub fn identity_request(sent: &[u8]) -> Result<Self, LayoutError> {
        const PREFIX: &[u8] = b"\r\nauthorization: Bearer ";
        let prefix_at = sent
            .windows(PREFIX.len())
            .position(|w| w == PREFIX)
            .ok_or(LayoutError::MissingHeader("authorization"))?;
        let value_start = prefix_at + PREFIX.len();
        let value_end = value_start
            + sent[value_start..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or(LayoutError::MissingHeader("authorization"))?;

        Ok(Self::revealing(
            [0..value_start, value_end..sent.len()],
            sent.len(),
        ))
    }

    /// The identity response: the two identity members with their full delimiters,
    /// and nothing else.
    ///
    /// Each member is revealed whole -- delimiter, value and closing byte -- so the
    /// verifier reads that field's value rather than a substring of a neighbouring
    /// one, and so the match sits inside a single revealed run rather than being
    /// spliced out of several. Everything between and around them is committed.
    ///
    /// # What committing the rest costs, and why it is taken
    ///
    /// Every reader on the verifying side scans revealed bytes: the per-range field
    /// read and the cross-range delimiter count alike. A commitment is invisible to
    /// all of them. So a response that genuinely names an authoritative field twice
    /// lets a prover commit the real member and reveal the one it composed, and
    /// both checks then see exactly one. Uniqueness is a property of the document,
    /// and this establishes it over a part.
    ///
    /// Reaching that needs the PLATFORM to emit the duplicate. ASM-PROV-06 assumes
    /// it does not, and JSON escaping keeps a `","field":"` delimiter out of any
    /// value the account controls -- a quote inside a string is written `\"`, which
    /// does not match the template. A duplicate that reaches the REVEALED bytes is
    /// still caught on chain, in either range layout.
    ///
    /// What the commitments buy is that the rest of the response never reaches the
    /// chain. `GET /user` under an OAuth client holding a `user`-family scope
    /// returns the account's plan, private-repository counts, disk usage and
    /// two-factor state; revealing the response whole would publish all of it,
    /// permanently, for every bind.
    ///
    /// `id_field` and `handle_field` are both bare `&str`, and a call that
    /// transposes them still finds both members, still reveals both, and still
    /// tiles -- it just names the handle as the account's immutable identifier.
    /// Nothing downstream sees the swap: the layout is well formed and the
    /// verifier reads what it was given, so the mistake surfaces on chain as an
    /// offset rather than as a name. `IdShape` sitting between the two is luck,
    /// not protection. Both names come from one profile, so keep them together at
    /// the call site.
    ///
    /// The arguments are still taken and still checked. A response missing either
    /// member is a failure now rather than at the verifier, where the reason would
    /// be an offset rather than a name.
    pub fn identity_response(
        recv: &[u8],
        session: &IdentitySession,
    ) -> Result<Self, LayoutError> {
        let (id_field, handle_field) = (session.id_field, session.handle_field);

        // The bare-integer form takes its structural terminator with it, which is
        // what proves the revealed digits are the whole number.
        let quoted = session.id_shape == IdShape::JsonString;
        let id = compute_id_snippet_range(recv, id_field, quoted)
            .ok_or_else(|| LayoutError::MissingField(id_field.into()))?;
        let handle = compute_field_snippet_range(recv, handle_field)
            .ok_or_else(|| LayoutError::MissingField(handle_field.into()))?;

        // JSON member order is not fixed; `Self::revealing` sorts, so this does
        // not assume one.
        Ok(Self::revealing([id, handle], recv.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property every layout must have, checked directly rather than
    /// inferred from the ranges looking plausible.
    fn tiles(l: &Layout, len: usize) -> bool {
        let mut spans: Vec<Range<usize>> =
            l.reveal.iter().chain(l.commit.iter()).cloned().collect();
        spans.sort_by_key(|r| r.start);
        let mut at = 0usize;
        for s in spans {
            if s.start != at || s.end <= s.start {
                return false;
            }
            at = s.end;
        }
        at == len
    }

    /// The launch profiles these layouts are built for. Taking the arguments
    /// from the table rather than restating them is what makes these tests
    /// exercise the values a Platform Verifier actually compares against.
    fn x_token() -> TokenSession {
        libid_profiles::X
            .token
            .expect("x notarizes a token session")
    }

    fn x_identity() -> IdentitySession {
        libid_profiles::X
            .identity
            .expect("x notarizes an identity session")
    }

    fn github_token() -> TokenSession {
        libid_profiles::GITHUB
            .token
            .expect("github notarizes a token session")
    }

    const X_TOKEN_REQ: &[u8] =
        b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=xyz";

    #[test]
    fn a_bearer_split_by_chunk_framing_is_refused() {
        // The session Rust actually runs. Framing inside the committed range
        // means the circuit opens bytes the token service never returned, and
        // the on-chain framing check passes anyway because it reads the
        // delimiters either side of the commitment, not its contents.
        let mut recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in [
            r#"{"access_token":"ghu_AA"#,
            r#"BB","token_type":"bearer"}"#,
        ] {
            recv.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            recv.extend_from_slice(part.as_bytes());
            recv.extend_from_slice(b"\r\n");
        }
        recv.extend_from_slice(b"0\r\n\r\n");
        assert!(Layout::token_response(&recv).is_err());
    }

    #[test]
    fn an_empty_bearer_is_refused() {
        // The two reveals would be adjacent, the complement would commit
        // nothing, and `requireFramedCommitment` would find no bearer in a
        // direction that carries no commitment at all.
        let recv: &[u8] = br#"HTTP/1.1 200 OK"#;
        let recv = [recv, b"\r\n\r\n", br#"{"access_token":""}"#].concat();
        assert!(Layout::token_response(&recv).is_err());
    }

    #[test]
    fn a_bearer_carrying_structural_bytes_is_committed_whole() {
        // Only `"` closes the value. A scan stopping at `:` or `,` would
        // commit a prefix and REVEAL the rest of the bearer.
        let recv = [
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            br#"{"access_token":"gh:u,A}BC","token_type":"bearer"}"#,
        ]
        .concat();
        let l = Layout::token_response(&recv).unwrap();
        assert!(tiles(&l, recv.len()));
        assert!(l.commit.iter().any(|c| recv[c.clone()] == *b"gh:u,A}BC"));
        // And no revealed run holds any part of it.
        for r in &l.reveal {
            assert!(
                !recv[r.clone()].windows(3).any(|w| w == b"gh:"),
                "the bearer must not appear in a revealed range"
            );
        }
    }

    #[test]
    fn a_header_cannot_answer_for_the_body() {
        // The old scan started at byte zero, so a response header carrying the
        // delimiter was matched before the body's own member.
        let recv: &[u8] = concat!(
            "HTTP/1.1 200 OK\r\n",
            r#"x-echo: "access_token":"decoy""#,
            "\r\n\r\n",
            r#"{"access_token":"real"}"#,
        )
        .as_bytes();
        let l = Layout::token_response(recv).unwrap();
        let revealed: Vec<u8> = l
            .reveal
            .iter()
            .flat_map(|r| recv[r.clone()].to_vec())
            .collect();
        assert_eq!(revealed, br#""access_token":"""#.to_vec());
        // The committed run is the bearer in the BODY, not the decoy.
        let committed = l.commit.iter().find(|r| r.len() == 4).unwrap();
        assert_eq!(&recv[committed.clone()], b"real");
    }

    #[test]
    fn the_x_token_request_is_revealed_whole() {
        let l = Layout::token_request(X_TOKEN_REQ, &x_token()).unwrap();
        assert_eq!(l.reveal, vec![0..X_TOKEN_REQ.len()]);
        assert!(l.commit.is_empty(), "X hides nothing in its token request");
        assert!(tiles(&l, X_TOKEN_REQ.len()));
    }

    #[test]
    fn the_github_exchange_commits_only_its_secret() {
        let req: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
        let l = Layout::token_request(req, &github_token()).unwrap();
        assert_eq!(l.reveal.len(), 1);
        assert_eq!(l.commit.len(), 1);
        // The commitment is a suffix, which is why ordering it last matters.
        assert_eq!(l.commit[0].end, req.len());
        assert!(tiles(&l, req.len()));
        // The secret's bytes are inside the commitment, not the reveal.
        let revealed = &req[l.reveal[0].clone()];
        assert!(!revealed.windows(8).any(|w| w == b"deadbeef"));
    }

    #[test]
    fn a_missing_secret_is_an_error_not_a_silent_reveal() {
        assert_eq!(
            Layout::token_request(X_TOKEN_REQ, &github_token()),
            Err(LayoutError::MissingCredential)
        );
    }

    #[test]
    fn the_token_response_reveals_only_the_two_anchors() {
        let recv: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";
        let l = Layout::token_response(recv).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(
            recv[l.reveal[0].clone()].to_vec(),
            b"\"access_token\":\"".to_vec()
        );
        assert_eq!(recv[l.reveal[1].clone()].to_vec(), b"\"".to_vec());
        // The bearer is committed, between the two anchors.
        assert!(l.commit.iter().any(|c| recv[c.clone()] == *b"SECRETBEARER"));
    }

    #[test]
    fn the_identity_request_commits_only_the_bearer() {
        let sent: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer TOKENVALUE\r\nconnection: close\r\n\r\n";
        let l = Layout::identity_request(sent).unwrap();
        assert!(tiles(&l, sent.len()));
        assert_eq!(l.commit.len(), 1, "exactly one credential is hidden");
        assert_eq!(sent[l.commit[0].clone()].to_vec(), b"TOKENVALUE".to_vec());
        // And the framing bytes the verifier compares are revealed.
        let before = &sent[..l.commit[0].start];
        assert!(before.ends_with(b"\r\nauthorization: Bearer "));
        assert!(sent[l.commit[0].end..].starts_with(b"\r\n"));
    }

    #[test]
    fn a_request_without_the_credential_header_is_an_error() {
        assert_eq!(
            Layout::identity_request(
                b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n\r\n"
            ),
            Err(LayoutError::MissingHeader("authorization"))
        );
    }

    #[test]
    fn the_identity_response_reveals_both_members_whole() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"alice\"}}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(l.reveal.len(), 2);
        // Whole members, delimiters included -- so the verifier reads the
        // field's value and not a substring of the display name beside it.
        assert_eq!(
            recv[l.reveal[0].clone()].to_vec(),
            b"\"id\":\"2244994945\"".to_vec()
        );
        assert_eq!(
            recv[l.reveal[1].clone()].to_vec(),
            b"\"username\":\"alice\"".to_vec()
        );
    }

    #[test]
    fn a_response_that_names_the_handle_first_still_reveals_in_offset_order() {
        // JSON member order is not the platform's promise, and the arguments
        // are given id-first regardless. `Layout::revealing` is what reconciles
        // the two: `complement` walks the reveals taking each as starting where
        // the last one ended, so an unsorted pair reads as overlap and yields a
        // complement that tiles nothing -- a layout the Platform Verifier
        // refuses, with no honest ceremony able to produce an accepted one.
        //
        // Every other fixture here happens to serialize `id` first, so this is
        // the one that exercises the sort.
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"username\":\"alice\",\"id\":\"7\"}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(l.reveal.len(), 2);
        // Offset order, which here is the OPPOSITE of the argument order.
        assert_eq!(
            recv[l.reveal[0].clone()].to_vec(),
            b"\"username\":\"alice\"".to_vec()
        );
        assert_eq!(recv[l.reveal[1].clone()].to_vec(), b"\"id\":\"7\"".to_vec());
    }

    #[test]
    fn the_display_name_beside_a_member_stays_committed() {
        // The point of committing the rest: nothing but the two members and
        // their delimiters reaches the chain.
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"7\",\"name\":\"Al\",\"username\":\"alice\"}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert!(!l.commit.is_empty(), "the rest of the response is hidden");
        for r in &l.reveal {
            assert!(
                !recv[r.clone()].windows(2).any(|w| w == b"Al"),
                "the display name is inside a revealed range"
            );
        }
    }

    /// The one duplicate this layout cannot defend against, recorded so the
    /// assumption is visible on the prover side too.
    ///
    /// A response naming `username` twice lets the revealed range carry one
    /// member while the other stays committed, invisible to every reader on
    /// chain. Reaching it needs the platform to emit that document: ASM-PROV-06
    /// assumes it does not, and JSON escaping keeps the delimiter out of any
    /// value the account controls. The layout picks the first match and does
    /// not detect the second -- stated here rather than left to be discovered.
    #[test]
    fn a_response_naming_a_member_twice_reveals_only_one() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"7\",\"username\":\"victim\",\"username\":\"alice\"}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        let revealed: usize = l
            .reveal
            .iter()
            .map(|r| {
                recv[r.clone()]
                    .windows(11)
                    .filter(|w| *w == b"\"username\":")
                    .count()
            })
            .sum();
        assert_eq!(revealed, 1, "the second member is committed, not revealed");
    }

    #[test]
    fn a_missing_member_is_an_error() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"7\"}}";
        assert!(matches!(
            Layout::identity_response(recv, &x_identity()),
            Err(LayoutError::MissingField(_))
        ));
    }
}

#[cfg(test)]
mod tables {
    use super::profiles;

    /// The ceremony profiles and the identity system name the same platforms.
    ///
    /// Two generated tables, deliberately: one says how a handle normalizes,
    /// the other says what a session notarizes, and neither belongs inside the
    /// other. libid-contracts keeps them apart the same way and asserts they
    /// agree (`PlatformIdentity.t.sol::test_theTwoTablesAgree`), because a name
    /// bound through one path and read through the other is two keyspaces for
    /// one platform with nothing to make the divergence loud.
    ///
    /// Both crates are generated from libid-contracts, so this is not checking
    /// our transcription -- it is checking that a consumer holding BOTH at
    /// versions it chose independently holds one keyspace. They are separate
    /// crates with separate version requirements, and a lockfile can pin a pair
    /// that never shipped together.
    #[test]
    fn the_two_tables_name_the_same_platforms() {
        use libid_identity::handle_vectors::{
            PLATFORM_GITHUB_DOMAIN,
            PLATFORM_GOOGLE_DOMAIN,
            PLATFORM_X_DOMAIN,
        };

        assert_eq!(profiles::X.platform, PLATFORM_X_DOMAIN);
        assert_eq!(profiles::GITHUB.platform, PLATFORM_GITHUB_DOMAIN);
        assert_eq!(profiles::GOOGLE.platform, PLATFORM_GOOGLE_DOMAIN);
    }
}
