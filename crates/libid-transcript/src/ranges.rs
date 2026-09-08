//! TLS transcript parsing and byte-range helpers for selective disclosure.
//!
//! All functions operate on raw transcript bytes (`sent` / `recv`) and return
//! `Range<usize>` offsets into them. The revealed slices become Merkle leaves
//! that on-chain verifiers check, so every helper here fails closed: a range
//! that cannot be located contiguously in the RAW transcript (e.g. a JSON
//! snippet split across a chunk boundary) yields `None` rather than a
//! mis-resolved leaf.

use std::ops::Range;

use crate::{
    Error,
    Result,
};

/// Find the byte range of an HTTP header value in raw TLS data.
pub fn find_header_range(data: &[u8], name: &str) -> Option<Range<usize>> {
    let needle = format!("\r\n{}: ", name);
    let needle_bytes = needle.as_bytes();
    let start = data
        .windows(needle_bytes.len())
        .position(|w| w.eq_ignore_ascii_case(needle_bytes))?;
    let value_start = start.checked_add(needle_bytes.len())?;
    let value_end = data
        .get(value_start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .and_then(|pos| value_start.checked_add(pos))?;
    Some(value_start..value_end)
}

/// Extract an HTTP header value from raw TLS data.
pub fn extract_header(data: &[u8], name: &str) -> Option<String> {
    find_header_range(data, name)
        .map(|range| String::from_utf8_lossy(&data[range]).to_string())
}

/// Find the byte range of the HTTP request line in sent data.
pub fn find_request_line_range(sent: &[u8]) -> Range<usize> {
    let end = sent
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(sent.len());
    0..end
}

/// Find the byte range of the HTTP response body in received data.
pub fn find_response_body_range(recv: &[u8]) -> Option<Range<usize>> {
    let marker = b"\r\n\r\n";
    recv.windows(marker.len())
        .position(|w| w == marker)
        .and_then(|pos| pos.checked_add(marker.len()))
        .map(|body_start| body_start..recv.len())
}

/// Extract and decode the HTTP response body from received TLS data.
///
/// Handles both chunked and non-chunked transfer encodings.
pub fn extract_response_body(recv: &[u8]) -> Result<Vec<u8>> {
    let range = find_response_body_range(recv).ok_or_else(|| Error::Transcript {
        detail: "no response body found".into(),
    })?;
    let raw_body = &recv[range];

    if let Some(te) = extract_header(recv, "Transfer-Encoding") {
        if te.contains("chunked") {
            return decode_chunked_body(raw_body);
        }
    }

    Ok(raw_body.to_vec())
}

/// Join a chunked body's chunks.
///
/// Every malformed input is an error rather than a shorter body. The reveal
/// ranges are computed over what this returns, so a silent truncation would
/// have the prover select ranges over bytes the server never sent -- and the
/// notary would sign that selection without anyone noticing.
fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>> {
    let bad = |detail: &str| Error::Transcript {
        detail: format!("chunked body: {detail}"),
    };

    let mut out = Vec::new();
    let mut rest = raw;
    loop {
        let (header_len, size) = match httparse::parse_chunk_size(rest) {
            Ok(httparse::Status::Complete(v)) => v,
            Ok(httparse::Status::Partial) => {
                return Err(bad("ends inside a chunk header"))
            }
            Err(_) => return Err(bad("chunk size is not hexadecimal")),
        };
        if size == 0 {
            return Ok(out);
        }
        let size =
            usize::try_from(size).map_err(|_| bad("chunk larger than this machine"))?;
        let body_end = header_len
            .checked_add(size)
            .ok_or_else(|| bad("chunk length overflows"))?;
        let chunk = rest
            .get(header_len..body_end)
            .ok_or_else(|| bad("chunk is shorter than its declared size"))?;
        out.extend_from_slice(chunk);

        // The CRLF that closes a chunk. Its absence means the framing is not
        // what it claims, and the next size would be read from the wrong place.
        let after = rest
            .get(body_end..body_end + 2)
            .ok_or_else(|| bad("ends before a chunk terminator"))?;
        if after != b"\r\n" {
            return Err(bad("chunk is not terminated by CRLF"));
        }
        rest = &rest[body_end + 2..];
    }
}

/// Find the byte range of a JSON string field value.
pub fn find_json_field_range(body: &[u8], field: &str) -> Option<Range<usize>> {
    let needle = format!("\"{}\"", field);
    let pos = body
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())?;
    let after_key = pos.checked_add(needle.len())?;
    let colon = body
        .get(after_key..)?
        .iter()
        .position(|&b| b == b':')?
        .checked_add(after_key)?;
    let after_colon = colon.checked_add(1)?;
    let open_quote = body
        .get(after_colon..)?
        .iter()
        .position(|&b| b == b'"')?
        .checked_add(after_colon)?;
    let after_open = open_quote.checked_add(1)?;
    let close_quote = body
        .get(after_open..)?
        .iter()
        .position(|&b| b == b'"')?
        .checked_add(after_open)?;
    Some(after_open..close_quote)
}

/// Find the byte ranges that should be revealed to the notary: the request
/// line and the Host header.
pub fn find_notary_reveal_ranges(sent: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();

    let req_line = find_request_line_range(sent);
    let req_end = req_line.end.saturating_add(2).min(sent.len());
    ranges.push(0..req_end);

    if let Some(range) = find_header_range(sent, "Host") {
        let needle = "\r\nHost: ";
        let prefix_start = sent
            .windows(needle.len())
            .position(|w| w.eq_ignore_ascii_case(needle.as_bytes()));
        if let Some(start) = prefix_start {
            let header_end = range.end.saturating_add(2).min(sent.len());
            ranges.push(start..header_end);
        }
    }

    ranges
}

/// Find the byte ranges to commit to in the TLSNotary presentation.
pub fn find_presentation_commit_ranges(sent: &[u8]) -> Vec<Range<usize>> {
    find_notary_reveal_ranges(sent)
}

/// Compute the absolute recv-transcript byte range for a JSON field value.
///
/// Given the full `recv` transcript data and a JSON field name, this function:
/// 1. Finds the HTTP response body range in `recv`
/// 2. Decodes the body (handling chunked transfer encoding)
/// 3. Finds the field value range in the decoded body
/// 4. Maps it back to an absolute range in the raw `recv` data
///
/// Returns the absolute byte range within `recv` that contains just the
/// field's string value (without quotes).
pub fn compute_field_reveal_range(recv: &[u8], field_name: &str) -> Option<Range<usize>> {
    let body_range = find_response_body_range(recv)?;
    let raw_body = &recv[body_range.clone()];
    let decoded_body = extract_response_body(recv).ok()?;

    // Find field in decoded body to validate it exists
    let _decoded_field_range = find_json_field_range(&decoded_body, field_name)?;

    // For the actual byte range, search in the raw body (which may include
    // chunk framing). The field bytes are the same in both representations.
    let raw_field_range = find_json_field_range(raw_body, field_name)?;

    let start = body_range.start.checked_add(raw_field_range.start)?;
    let end = body_range.start.checked_add(raw_field_range.end)?;
    Some(start..end)
}

/// The `"key":"value"` member, from the key's opening quote through the
/// value's closing quote.
///
/// Unlike [`find_json_field_range`], which returns only the value bytes, this
/// returns the whole member -- the range a reveal layout selects.
///
/// # The template is the reader's
///
/// `CeremonyFields.tryJsonString` matches the literal `"<name>":"`, so this
/// matches the same bytes. Anything looser picks a range the reader cannot
/// read: a body written `"login" : "octocat"` would be revealed here and then
/// met with `FieldNotFound` on chain, which is the same refusal reported where
/// nobody can see why. Failing here fails it where the reason is visible.
///
/// Uniqueness is NOT checked here, and that is deliberate. The reader refuses
/// a delimiter matching twice in the bytes it was shown (REQ-COMMON-19A), and
/// which bytes those are is exactly what a layout decides -- so
/// `identity_response` reveals one member and commits the other, and the
/// reader sees one. Refusing a second occurrence here would only stop an
/// honest prover from building that layout; a dishonest one does not run this
/// code at all.
pub fn find_json_snippet_range(body: &[u8], field: &str) -> Option<Range<usize>> {
    JsonMember::in_body(body, field).map(|member| member.member)
}

/// A `"field":"value"` member, and the value inside it.
///
/// Two ranges rather than one because a caller that reveals the delimiters and
/// commits the value needs both boundaries, and deriving the inner one from the
/// outer one means restating the template -- which is a second place to change
/// the field name and one place to forget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonMember {
    /// The whole member, both delimiters included.
    pub member: Range<usize>,
    /// The value alone, between the quotes. Empty when the value is `""`.
    pub value: Range<usize>,
}

impl JsonMember {
    /// The member named `field` in `body`, with offsets INTO `body`.
    ///
    /// Raw bytes in, raw offsets out: this scans whatever it is handed, so a
    /// caller passing a whole HTTP response gets whichever match comes first --
    /// a header's, if a header carries the delimiter. [`JsonMember::in_response`]
    /// is the one that locates the body first, and is what a caller building a
    /// reveal layout wants.
    ///
    /// A constructor on the type it produces: `json_member_in` restated the type
    /// in the function name, stranded a preposition on the end of it, and left
    /// the coordinate system -- the thing this module gets wrong most
    /// expensively -- unsaid.
    ///
    /// The template it matches, and why that template is exactly the reader's,
    /// is argued on [`find_json_snippet_range`], which is the public face of
    /// this scan.
    fn in_body(body: &[u8], field: &str) -> Option<Self> {
        let needle = format!("\"{field}\":\"");
        let start = find_first(body, needle.as_bytes())?;
        let value = start.checked_add(needle.len())?;
        let close = body
            .get(value..)?
            .iter()
            .position(|&b| b == b'"')?
            .checked_add(value)?;
        Some(Self {
            // From the opening `"` of the key through the closing `"` of the value.
            member: start..close.checked_add(1)?,
            value: value..close,
        })
    }

    /// The member named `field_name` in an HTTP response, with offsets into the
    /// RAW `recv` transcript.
    ///
    /// For a caller that reveals a member's delimiters and commits what sits
    /// between them: both boundaries come from the scan that found them, so no
    /// caller restates the template to recover one.
    ///
    /// The offsets are the whole difference from `in_body`, and the reason the
    /// two are named apart rather than left to a `find_`/`compute_` prefix
    /// nobody can decode. A reveal layout selects ranges of the TRANSCRIPT, so a
    /// body-relative range handed to one selects bytes somewhere up in the
    /// response headers -- a range that is well formed, signed, and pointing at
    /// the wrong thing.
    pub fn in_response(recv: &[u8], field_name: &str) -> Option<Self> {
        let body_range = find_response_body_range(recv)?;
        let raw_body = &recv[body_range.clone()];
        let decoded_body = extract_response_body(recv).ok()?;

        // Found in both: the decoded body says the member exists, the raw body says
        // where it sits, and the two must hold the same bytes.
        let decoded = Self::in_body(&decoded_body, field_name)?;
        let raw = Self::in_body(raw_body, field_name)?;
        require_contiguous(
            raw_body.get(raw.member.clone())?,
            decoded_body.get(decoded.member)?,
        )?;

        let at = |offset: usize| body_range.start.checked_add(offset);
        Some(Self {
            member: at(raw.member.start)?..at(raw.member.end)?,
            value: at(raw.value.start)?..at(raw.value.end)?,
        })
    }
}

/// The first occurrence of `needle`, or nothing.
fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The raw bytes are the member, and not the member with framing through it.
///
/// A chunked body carries `\r\n<size>\r\n` between chunks, and that framing
/// holds no quote, comma or brace -- so a member split across a boundary is
/// found in the decoded body AND in the raw one, and the raw range silently
/// spans the framing. What that range selects is not the member: revealed, it
/// puts framing inside the handle a verifier reads; committed, it puts framing
/// inside the bearer a circuit opens against the clean value the caller was
/// handed. Re-framing cannot repair it, because a commitment covers one
/// contiguous run and this member is two.
///
/// So the session is refused here, where the reason is a decodable body rather
/// than an unopenable commitment three components later.
fn require_contiguous(raw: &[u8], decoded: &[u8]) -> Option<()> {
    (raw == decoded).then_some(())
}

/// Find the byte range of a bare (unquoted) JSON number snippet:
/// `"key":<number>,`. The range runs from the key's opening `"` through the
/// trailing `,` that follows the number (matching the on-chain `idSuffix=,`).
///
/// Returns `None` only when neither a `,` nor a `}` terminator follows the
/// number; both terminators are included in the range (on-chain `_extractId`
/// scans digits and stops at either).
pub fn find_json_bare_snippet_range(body: &[u8], field: &str) -> Option<Range<usize>> {
    let needle = format!("\"{field}\":");
    let start = find_first(body, needle.as_bytes())?;
    let from = start.checked_add(needle.len())?;

    // Digits, then the byte that closes them -- the order `tryJsonInteger`
    // reads in. Scanning instead to the first `,` or `}` would accept
    // `"id":"7",`, a quoted value returned as though it were a number: the
    // chain then refuses it as noncanonical, which is the same answer given
    // where nobody can see the reason.
    let rest = body.get(from..)?;
    let width = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if width == 0 {
        return None;
    }
    // A leading zero is noncanonical, and `0` alone is not a leading zero.
    if width > 1 && rest[0] == b'0' {
        return None;
    }

    // The terminator is revealed with the digits: it is what proves they are
    // the whole number rather than a prefix of a longer one, and the profile
    // fixes it as `,` or `}` and no other byte (REQ-PLAT-51).
    let term = from.checked_add(width)?;
    match body.get(term) {
        Some(b',') | Some(b'}') => Some(start..term.checked_add(1)?),
        _ => None,
    }
}

/// Like [`compute_field_reveal_range`] but returns the range covering the
/// full JSON snippet `"key":"value"` instead of just the value.
///
/// The revealed bytes become a Merkle leaf that the contract can verify
/// against the expected `abi.encodePacked(handlePrefix, username, '"')`.
pub fn compute_field_snippet_range(
    recv: &[u8],
    field_name: &str,
) -> Option<Range<usize>> {
    JsonMember::in_response(recv, field_name).map(|found| found.member)
}

/// Like [`compute_id_snippet_range`] but only matches `field_name` after the
/// first occurrence of `anchor_field` (disambiguates a non-unique id field).
pub fn compute_id_snippet_range_after(
    recv: &[u8],
    field_name: &str,
    quoted: bool,
    anchor_field: &str,
) -> Option<Range<usize>> {
    let body_range = find_response_body_range(recv)?;
    let raw_body = &recv[body_range.clone()];

    // Include the `:` so we match the JSON KEY `"user":` — not a substring of a
    // user-controlled body field (whose quotes are JSON-escaped) nor a sibling
    // key like `"user_view_type"`.
    let anchor_needle = format!("\"{}\":", anchor_field);

    // Validate the anchored id against the DECODED body (chunk-framing stripped),
    // so a body that is chunked or contains decoy bytes can't drive the result.
    // The bytes it finds are kept, to be compared with the raw ones below.
    let decoded = extract_response_body(recv).ok()?;
    let decoded_member = {
        let danchor = decoded
            .windows(anchor_needle.len())
            .position(|w| w == anchor_needle.as_bytes())?;
        let from = danchor.checked_add(anchor_needle.len())?;
        let dsub = decoded.get(from..)?;
        let rel = if quoted {
            find_json_snippet_range(dsub, field_name)?
        } else {
            find_json_bare_snippet_range(dsub, field_name)?
        };
        dsub.get(rel)?
    };

    // The Merkle leaf is over the RAW transcript, so map the range there.
    let anchor_pos = raw_body
        .windows(anchor_needle.len())
        .position(|w| w == anchor_needle.as_bytes())?;
    let search_from = anchor_pos.checked_add(anchor_needle.len())?;
    let sub = raw_body.get(search_from..)?;

    let rel = if quoted {
        find_json_snippet_range(sub, field_name)?
    } else {
        find_json_bare_snippet_range(sub, field_name)?
    };
    require_contiguous(sub.get(rel.clone())?, decoded_member)?;

    let base = body_range.start.checked_add(search_from)?;
    Some(base.checked_add(rel.start)?..base.checked_add(rel.end)?)
}

/// Compute the absolute recv-transcript range for an id snippet, dispatching on
/// quotedness: `quoted` → `"id":"<id>"`, otherwise the bare `"id":<n>[,}]` form.
///
/// Returns `None` if the field is absent. Both `,`- and `}`-terminated bare
/// numbers are matched (on-chain `_extractId` scans digits past either).
pub fn compute_id_snippet_range(
    recv: &[u8],
    field_name: &str,
    quoted: bool,
) -> Option<Range<usize>> {
    if quoted {
        return compute_field_snippet_range(recv, field_name);
    }
    let body_range = find_response_body_range(recv)?;
    let raw_body = &recv[body_range.clone()];
    let decoded_body = extract_response_body(recv).ok()?;

    let decoded_range = find_json_bare_snippet_range(&decoded_body, field_name)?;
    let raw_snippet_range = find_json_bare_snippet_range(raw_body, field_name)?;
    require_contiguous(
        raw_body.get(raw_snippet_range.clone())?,
        decoded_body.get(decoded_range)?,
    )?;

    let start = body_range.start.checked_add(raw_snippet_range.start)?;
    let end = body_range.start.checked_add(raw_snippet_range.end)?;
    Some(start..end)
}

#[cfg(test)]
mod tests {
    /// A chunk header that is not a hex size used to end the body silently:
    /// the size parsed as `unwrap_or(0)`, the loop hit `break`, and the caller
    /// got a short body with no error. The reveal ranges are computed from
    /// that body, so the prover would select them over bytes the server never
    /// sent -- and never learn.
    #[test]
    fn a_malformed_chunk_size_is_an_error_not_a_short_body() {
        let recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nhello\r\nzz\r\nworld\r\n0\r\n\r\n";
        assert!(super::extract_response_body(recv).is_err());
    }

    #[test]
    fn a_truncated_chunk_is_an_error_too() {
        // The size says 20 bytes and 5 follow.
        let recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
14\r\nhello";
        assert!(super::extract_response_body(recv).is_err());
    }

    use super::*;

    #[test]
    fn find_json_field_range_simple() {
        let body = br#"{"login":"octocat","id":123}"#;
        let range = find_json_field_range(body, "login").unwrap();
        assert_eq!(&body[range], b"octocat");
    }

    #[test]
    fn find_json_field_range_nested() {
        let body = br#"{"user":{"login":"octocat"},"body":"hello"}"#;
        let range = find_json_field_range(body, "login").unwrap();
        assert_eq!(&body[range], b"octocat");

        let range = find_json_field_range(body, "body").unwrap();
        assert_eq!(&body[range], b"hello");
    }

    #[test]
    fn find_json_field_range_x_tweet() {
        let body = br#"{"data":[{"text":"@libid greet @bob with 1 TST","id":"123"}],"includes":{"users":[{"username":"alice"}]}}"#;
        let range = find_json_field_range(body, "text").unwrap();
        assert_eq!(&body[range], b"@libid greet @bob with 1 TST");

        let range = find_json_field_range(body, "username").unwrap();
        assert_eq!(&body[range], b"alice");
    }

    #[test]
    fn compute_field_reveal_range_from_http() {
        // Simulate a minimal HTTP response with a JSON body
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"body\":\"hello world\",\"user\":{\"login\":\"alice\"}}";

        let range = compute_field_reveal_range(recv, "body").unwrap();
        assert_eq!(&recv[range], b"hello world");

        let range = compute_field_reveal_range(recv, "login").unwrap();
        assert_eq!(&recv[range], b"alice");
    }

    #[test]
    fn compute_field_reveal_range_missing_field() {
        let recv =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"foo\":\"bar\"}";
        assert!(compute_field_reveal_range(recv, "missing").is_none());
    }

    #[test]
    fn extract_response_body_decodes_chunked() {
        let recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1,\r\n8\r\n\"b\":\"x\"}\r\n0\r\n\r\n";
        let body = extract_response_body(recv).unwrap();
        assert_eq!(body, br#"{"a":1,"b":"x"}"#);
    }

    #[test]
    fn find_notary_reveal_ranges_covers_request_line_and_host() {
        let sent = b"GET /2/users/me HTTP/1.1\r\nHost: api.x.com\r\nAccept: application/json\r\n\r\n";
        let ranges = find_notary_reveal_ranges(sent);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&sent[ranges[0].clone()], b"GET /2/users/me HTTP/1.1\r\n");
        assert_eq!(&sent[ranges[1].clone()], b"\r\nHost: api.x.com\r\n");
        assert_eq!(find_presentation_commit_ranges(sent), ranges);
    }

    #[test]
    fn find_json_snippet_range_simple() {
        let body = br#"{"login":"octocat","id":123}"#;
        let range = find_json_snippet_range(body, "login").unwrap();
        assert_eq!(&body[range], br#""login":"octocat""#);
    }

    #[test]
    fn find_json_snippet_range_nested() {
        let body = br#"{"user":{"login":"octocat"},"body":"hello"}"#;
        let range = find_json_snippet_range(body, "login").unwrap();
        assert_eq!(&body[range], br#""login":"octocat""#);
    }

    #[test]
    fn a_second_member_is_left_for_the_layout_to_commit() {
        // Not refused here: the reader's uniqueness rule is over the bytes it
        // was shown, and the layout is what decides those. `identity_response`
        // reveals this one and commits the rest, so the reader sees one.
        let body = br#"{"login":"octocat","user":{"login":"impostor"}}"#;
        let range = find_json_snippet_range(body, "login").unwrap();
        assert_eq!(&body[range], br#""login":"octocat""#);

        let bare = br#"{"id":1,"user":{"id":2}}"#;
        let range = find_json_bare_snippet_range(bare, "id").unwrap();
        assert_eq!(&bare[range], br#""id":1,"#);
    }

    #[test]
    fn a_spaced_member_is_refused_because_the_reader_refuses_it() {
        // The on-chain needle is the literal `"login":"`. Selecting a range
        // here that the reader cannot read only moves the same refusal to
        // where its reason is invisible.
        let body = br#"{"login" : "octocat"}"#;
        assert!(find_json_snippet_range(body, "login").is_none());

        let bare = br#"{"id" : 123}"#;
        assert!(find_json_bare_snippet_range(bare, "id").is_none());
    }

    #[test]
    fn a_quoted_value_is_not_a_bare_number() {
        // `tryJsonInteger` scans DIGITS and then demands the terminator. A scan
        // that instead ran to the first `,` would return `"id":"7",` here, and
        // the chain would refuse it as noncanonical -- the same answer, given
        // where the reason is not visible.
        let body = br#"{"login":"octocat","id":"7","x":1}"#;
        assert!(find_json_bare_snippet_range(body, "id").is_none());
    }

    #[test]
    fn a_leading_zero_is_refused_but_zero_itself_is_not() {
        // `end - at > 1 && data[at] == "0"` on chain: `0123` is noncanonical,
        // `0` is just zero.
        assert!(find_json_bare_snippet_range(br#"{"id":0123,"x":1}"#, "id").is_none());
        let zero = br#"{"id":0,"x":1}"#;
        let range = find_json_bare_snippet_range(zero, "id").unwrap();
        assert_eq!(&zero[range], br#""id":0,"#);
    }

    #[test]
    fn a_terminator_the_profile_does_not_fix_is_refused() {
        // Only `,` and `}` close the digits. A `]` means the id sat in an array
        // the profile never described.
        assert!(find_json_bare_snippet_range(br#"{"a":[1,"id":7]}"#, "id").is_none());
        // And digits running to the end of the range have no terminator at all,
        // which is `Found.None` on chain rather than a value.
        assert!(find_json_bare_snippet_range(br#"{"id":7"#, "id").is_none());
    }

    #[test]
    fn a_lookalike_key_does_not_match() {
        // `"node_id":` contains `id":` but not `"id":` -- the full delimiter is
        // what keeps a neighbouring member out, on both sides.
        let body = br#"{"node_id":"MDQ=","id":123}"#;
        let range = find_json_bare_snippet_range(body, "id").unwrap();
        assert_eq!(&body[range], br#""id":123}"#);
    }

    #[test]
    fn find_json_snippet_range_email() {
        let body = br#"{"email":"alice@example.com","verified":true}"#;
        let range = find_json_snippet_range(body, "email").unwrap();
        assert_eq!(&body[range], br#""email":"alice@example.com""#);
    }

    #[test]
    fn compute_field_snippet_range_from_http() {
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"body\":\"hello world\",\"user\":{\"login\":\"alice\"}}";

        let range = compute_field_snippet_range(recv, "login").unwrap();
        assert_eq!(&recv[range], br#""login":"alice""#);

        let range = compute_field_snippet_range(recv, "body").unwrap();
        assert_eq!(&recv[range], br#""body":"hello world""#);
    }

    /// A chunked response whose `field` value is cut in half by a chunk
    /// boundary. The framing carries no quote, comma or brace, so every scan
    /// here runs straight through it.
    fn straddling(head: &str, tail: &str) -> Vec<u8> {
        let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in [head, tail] {
            out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            out.extend_from_slice(part.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    /// The property every caller of `JsonMember::in_response` depends on: the
    /// value sits inside the member, and what the member holds either side of
    /// it is exactly the two delimiters. A boundary that drifts breaks this
    /// before it reaches a layout, where the symptom is a committed bearer with
    /// a quote in it.
    fn assert_brackets(recv: &[u8], found: &JsonMember, field: &str, value: &[u8]) {
        assert!(
            found.member.start <= found.value.start
                && found.value.end <= found.member.end,
            "the value must sit inside the member"
        );
        assert_eq!(&recv[found.value.clone()], value, "value bytes");
        assert_eq!(
            &recv[found.member.start..found.value.start],
            format!("\"{field}\":\"").as_bytes(),
            "opening delimiter"
        );
        assert_eq!(
            &recv[found.value.end..found.member.end],
            b"\"",
            "closing quote"
        );
    }

    #[test]
    fn the_member_brackets_its_value_with_the_two_delimiters() {
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"ghu_ABC\",\"x\":1}";
        let found = JsonMember::in_response(recv, "access_token").unwrap();
        assert_brackets(recv, &found, "access_token", b"ghu_ABC");
    }

    #[test]
    fn a_value_carrying_structural_bytes_still_ends_at_its_quote() {
        // Only `"` closes a JSON string, so a value holding `:`, `,` or `}`
        // must not shorten the member -- a scan that stopped at one would
        // commit a prefix of the bearer and reveal the rest of it.
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"a:b,c}d\",\"x\":1}";
        let found = JsonMember::in_response(recv, "access_token").unwrap();
        assert_brackets(recv, &found, "access_token", b"a:b,c}d");
    }

    #[test]
    fn an_empty_value_is_found_with_an_empty_range() {
        // Found, not refused: whether an empty value is usable is the caller's
        // rule, and `token_response` has its own reason to refuse one.
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"\"}";
        let found = JsonMember::in_response(recv, "access_token").unwrap();
        assert!(found.value.is_empty());
        assert_eq!(&recv[found.member.clone()], b"\"access_token\":\"\"");
    }

    #[test]
    fn the_member_range_is_the_snippet_range() {
        // `compute_field_snippet_range` is this with the value dropped, and the
        // two must not drift apart.
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"login\":\"octocat\",\"id\":1}";
        assert_eq!(
            JsonMember::in_response(recv, "login").unwrap().member,
            compute_field_snippet_range(recv, "login").unwrap()
        );
    }

    #[test]
    fn a_member_split_by_chunk_framing_is_refused() {
        // Found in both bodies, and the raw range spans `\r\n<size>\r\n` in the
        // middle of the value. Revealed it would put framing inside the handle
        // a verifier reads; committed, inside the bearer a circuit opens.
        let recv = straddling(r#"{"login":"oct"#, r#"ocat","id":1}"#);
        assert!(compute_field_snippet_range(&recv, "login").is_none());
    }

    #[test]
    fn a_bare_id_split_by_chunk_framing_is_refused() {
        let recv = straddling(r#"{"login":"octocat","id":12"#, r#"34,"x":1}"#);
        assert!(compute_id_snippet_range(&recv, "id", false).is_none());
    }

    #[test]
    fn an_anchored_id_split_by_chunk_framing_is_refused() {
        let recv = straddling(r#"{"user":{"id":"12"#, r#"34"}}"#);
        assert!(compute_id_snippet_range_after(&recv, "id", true, "user").is_none());
    }

    #[test]
    fn a_chunked_member_inside_one_chunk_still_resolves() {
        // The point is contiguity, not chunking: a body that happens to be
        // chunked is fine as long as the member sits in one piece.
        let recv = straddling(r#"{"login":"octocat","#, r#""id":1}"#);
        let range = compute_field_snippet_range(&recv, "login").unwrap();
        assert_eq!(&recv[range], br#""login":"octocat""#);
    }

    #[test]
    fn compute_field_snippet_range_missing_field() {
        let recv =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"foo\":\"bar\"}";
        assert!(compute_field_snippet_range(recv, "missing").is_none());
    }

    // ── Bare-number id snippets (GitHub) ───────────────────────────────────

    #[test]
    fn find_json_bare_snippet_range_comma_terminated() {
        // GitHub `/user`: id is a bare number followed by more fields.
        let body = br#"{"login":"octocat","id":123,"node_id":"MDQ="}"#;
        let range = find_json_bare_snippet_range(body, "id").unwrap();
        assert_eq!(&body[range], br#""id":123,"#);
    }

    #[test]
    fn find_json_bare_snippet_range_brace_terminated() {
        // id is the last field — terminated by `}`. The snippet includes the
        // `}`; `CeremonyFields.tryJsonInteger` scans digits and stops at it.
        let body = br#"{"login":"octocat","id":123}"#;
        let range = find_json_bare_snippet_range(body, "id").unwrap();
        assert_eq!(&body[range], br#""id":123}"#);
    }

    #[test]
    fn compute_id_snippet_range_bare_comma() {
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"login\":\"octocat\",\"id\":123,\"node_id\":\"x\"}";
        let range = compute_id_snippet_range(recv, "id", false).unwrap();
        assert_eq!(&recv[range], br#""id":123,"#);
    }

    #[test]
    fn compute_id_snippet_range_bare_brace_terminated() {
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"login\":\"octocat\",\"id\":123}";
        let range = compute_id_snippet_range(recv, "id", false).unwrap();
        assert_eq!(&recv[range], br#""id":123}"#);
    }

    #[test]
    fn compute_id_snippet_range_quoted_delegates() {
        // X: quoted id snippet `"id":"123"`.
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"id\":\"123\",\"username\":\"alice\"}}";
        let range = compute_id_snippet_range(recv, "id", true).unwrap();
        assert_eq!(&recv[range], br#""id":"123""#);
    }

    #[test]
    fn compute_id_snippet_range_after_anchor() {
        // The id under `"user":` is the one that must resolve, not the decoy
        // earlier in the body.
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":999,\"user\":{\"login\":\"octocat\",\"id\":123,\"x\":1}}";
        let range = compute_id_snippet_range_after(recv, "id", false, "user").unwrap();
        assert_eq!(&recv[range], br#""id":123,"#);
    }
}
