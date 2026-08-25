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
    #[error("the response has no status line, so nothing says the server agreed")]
    NoStatusLine,
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

/// A one-range reveal list. Spelled this way because a `vec![a..b]` literal
/// trips a lint that exists to catch `vec![0; n]` typos.
fn one(range: Range<usize>) -> Vec<Range<usize>> {
    core::iter::once(range).collect()
}

fn layout(reveal: Vec<Range<usize>>, len: usize) -> Layout {
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
    secret_field: Option<&str>,
) -> Result<Layout, LayoutError> {
    let Some(field) = secret_field else {
        return Ok(layout(one(0..sent.len()), sent.len()));
    };

    // `&client_secret=` begins the committed tail. The profile orders it last
    // under REQ-COMMON-22 precisely so this is a suffix and not a hole.
    let needle = format!("&{field}=");
    let start = sent
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .ok_or(LayoutError::MissingCredential)?;
    Ok(layout(one(0..start), sent.len()))
}

/// The token response: the `"access_token":"` delimiter and its closing quote
/// are revealed, and everything else -- the bearer included -- is committed.
///
/// Those two anchors are what identify the committed bearer. Without them the
/// committed range is indistinguishable from a `refresh_token` value, or any
/// other substring the prover chose to commit (REQ-PLAT-57, REQ-PLAT-58).
/// The status line, from the origin to its CRLF.
///
/// Revealed in every response layout so the Platform Verifier can see that the
/// server agreed. Without it, consent is inferred from the wanted fields
/// happening to be present -- which is an argument about what an error body
/// does not contain, not a check.
///
/// Anchored at offset zero, so the verifier reads it as the status line rather
/// than as bytes that look like one.
fn status_line(recv: &[u8]) -> Result<Range<usize>, LayoutError> {
    let end = recv
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(LayoutError::NoStatusLine)?;
    Ok(0..end)
}

pub fn token_response(recv: &[u8]) -> Result<Layout, LayoutError> {
    const ANCHOR: &[u8] = b"\"access_token\":\"";
    let anchor_start = recv
        .windows(ANCHOR.len())
        .position(|w| w == ANCHOR)
        .ok_or_else(|| LayoutError::MissingField("access_token".into()))?;
    let value_start = anchor_start + ANCHOR.len();
    let value_end = value_start
        + recv[value_start..]
            .iter()
            .position(|&b| b == b'"')
            .ok_or_else(|| LayoutError::MissingField("access_token".into()))?;

    Ok(layout(
        vec![
            status_line(recv)?,
            anchor_start..value_start,
            value_end..value_end + 1,
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
pub fn identity_request(sent: &[u8]) -> Result<Layout, LayoutError> {
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

    Ok(layout(
        vec![0..value_start, value_end..sent.len()],
        sent.len(),
    ))
}

/// Which shape the platform's immutable identifier takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdShape {
    /// X: `"id":"2244994945"`.
    JsonString,
    /// GitHub: `"id":583231,` -- the terminator is revealed with it, because it
    /// is what proves the digits are the whole number rather than a prefix.
    JsonInteger,
}

/// The identity response: the two identity members with their full delimiters,
/// and nothing else.
///
/// Each member is revealed whole -- delimiter, value and closing byte -- so the
/// verifier reads that field's value rather than a substring of a neighbouring
/// one, and so the match sits inside a single revealed run rather than being
/// spliced out of several.
pub fn identity_response(
    recv: &[u8],
    id_field: &str,
    id_shape: IdShape,
    handle_field: &str,
) -> Result<Layout, LayoutError> {
    // The bare-integer form takes its structural terminator with it, which is
    // what proves the revealed digits are the whole number.
    let id = compute_id_snippet_range(recv, id_field, id_shape == IdShape::JsonString)
        .ok_or_else(|| LayoutError::MissingField(id_field.into()))?;
    let handle = compute_field_snippet_range(recv, handle_field)
        .ok_or_else(|| LayoutError::MissingField(handle_field.into()))?;

    // JSON member order is not fixed, so sort rather than assume. The status
    // line is first by construction, but sorting covers it too.
    let mut reveal = vec![status_line(recv)?, id, handle];
    reveal.sort_by_key(|r| r.start);
    Ok(layout(reveal, recv.len()))
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

    const X_TOKEN_REQ: &[u8] =
        b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=xyz";

    #[test]
    fn the_x_token_request_is_revealed_whole() {
        let l = token_request(X_TOKEN_REQ, None).unwrap();
        assert_eq!(l.reveal, vec![0..X_TOKEN_REQ.len()]);
        assert!(l.commit.is_empty(), "X hides nothing in its token request");
        assert!(tiles(&l, X_TOKEN_REQ.len()));
    }

    #[test]
    fn the_github_exchange_commits_only_its_secret() {
        let req: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
        let l = token_request(req, Some("client_secret")).unwrap();
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
            token_request(X_TOKEN_REQ, Some("client_secret")),
            Err(LayoutError::MissingCredential)
        );
    }

    /// Consent is a fact about the response, not an inference from what an
    /// error body happens not to contain. Both layouts reveal it, at offset
    /// zero, so the verifier reads a status line rather than bytes that look
    /// like one.
    #[test]
    fn every_response_layout_reveals_the_status_line_at_the_origin() {
        let token: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"X\"}";
        let identity: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"1\",\"username\":\"a\"}";

        for l in [
            token_response(token).unwrap(),
            identity_response(identity, "id", IdShape::JsonString, "username").unwrap(),
        ] {
            assert_eq!(l.reveal[0].start, 0);
            assert_eq!(l.reveal[0].end, 15);
        }
    }

    /// A response with no CRLF has no status line to reveal, and a layout that
    /// silently omitted it would produce an attestation the verifier refuses
    /// for a reason the prover cannot see.
    #[test]
    fn a_response_without_a_status_line_is_refused() {
        // Carries the field, so it gets past the anchor search and fails on
        // the thing under test rather than before it.
        assert_eq!(
            token_response(b"{\"access_token\":\"X\"}").unwrap_err(),
            LayoutError::NoStatusLine
        );
    }

    #[test]
    fn the_token_response_reveals_only_the_two_anchors() {
        let recv: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";
        let l = token_response(recv).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(
            recv[l.reveal[0].clone()].to_vec(),
            b"HTTP/1.1 200 OK".to_vec()
        );
        assert_eq!(
            recv[l.reveal[1].clone()].to_vec(),
            b"\"access_token\":\"".to_vec()
        );
        assert_eq!(recv[l.reveal[2].clone()].to_vec(), b"\"".to_vec());
        // The bearer is committed, between the two anchors.
        assert!(l.commit.iter().any(|c| recv[c.clone()] == *b"SECRETBEARER"));
    }

    #[test]
    fn the_identity_request_commits_only_the_bearer() {
        let sent: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer TOKENVALUE\r\nconnection: close\r\n\r\n";
        let l = identity_request(sent).unwrap();
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
            identity_request(b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n\r\n"),
            Err(LayoutError::MissingHeader("authorization"))
        );
    }

    #[test]
    fn the_x_identity_response_reveals_both_members_whole() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"alice\"}}";
        let l = identity_response(recv, "id", IdShape::JsonString, "username").unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(l.reveal.len(), 3);
        assert_eq!(
            recv[l.reveal[0].clone()].to_vec(),
            b"HTTP/1.1 200 OK".to_vec()
        );
        // Whole members, delimiters included -- so the verifier reads the
        // field's value and not a substring of the display name beside it.
        assert_eq!(
            recv[l.reveal[1].clone()].to_vec(),
            b"\"id\":\"2244994945\"".to_vec()
        );
        assert_eq!(
            recv[l.reveal[2].clone()].to_vec(),
            b"\"username\":\"alice\"".to_vec()
        );
        // The display name stays committed.
        assert!(l
            .commit
            .iter()
            .any(|c| recv[c.clone()].windows(4).any(|w| w == b"name")));
    }

    #[test]
    fn a_missing_member_is_an_error() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"7\"}}";
        assert!(matches!(
            identity_response(recv, "id", IdShape::JsonString, "username"),
            Err(LayoutError::MissingField(_))
        ));
    }
}
