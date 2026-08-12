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
            return Ok(decode_chunked_body(raw_body));
        }
    }

    Ok(raw_body.to_vec())
}

fn decode_chunked_body(raw: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        let size_end = match raw
            .get(pos..)
            .and_then(|s| s.windows(2).position(|w| w == b"\r\n"))
        {
            Some(p) => match pos.checked_add(p) {
                Some(v) => v,
                None => break,
            },
            None => break,
        };
        let size_str = std::str::from_utf8(raw.get(pos..size_end).unwrap_or_default())
            .unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if chunk_size == 0 {
            break;
        }
        let data_start = match size_end.checked_add(2) {
            Some(v) => v,
            None => break,
        };
        let data_end = match data_start.checked_add(chunk_size) {
            Some(v) => v,
            None => break,
        };
        if data_end > raw.len() {
            break;
        }
        result.extend_from_slice(&raw[data_start..data_end]);
        pos = match data_end.checked_add(2) {
            Some(v) => v,
            None => break,
        };
    }
    result
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

/// Find the byte range of a full JSON key-value snippet: `"key":"value"`.
///
/// Unlike [`find_json_field_range`] which returns only the value bytes,
/// this returns the range from the opening `"` of the key to the closing
/// `"` of the value (inclusive).
pub fn find_json_snippet_range(body: &[u8], field: &str) -> Option<Range<usize>> {
    let needle = format!("\"{}\"", field);
    let pos = body
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())?;
    // pos points to the opening `"` of the key.
    // Now find the closing `"` of the value (same logic as find_json_field_range).
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
    // Range: from opening `"` of key to after the closing `"` of value.
    Some(pos..close_quote.checked_add(1)?)
}

/// Find the byte range of a bare (unquoted) JSON number snippet:
/// `"key":<number>,`. The range runs from the key's opening `"` through the
/// trailing `,` that follows the number (matching the on-chain `idSuffix=,`).
///
/// Returns `None` only when neither a `,` nor a `}` terminator follows the
/// number; both terminators are included in the range (on-chain `_extractId`
/// scans digits and stops at either).
pub fn find_json_bare_snippet_range(body: &[u8], field: &str) -> Option<Range<usize>> {
    let needle = format!("\"{}\"", field);
    let pos = body
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())?;
    // pos points to the opening `"` of the key.
    let after_key = pos.checked_add(needle.len())?;
    let colon = body
        .get(after_key..)?
        .iter()
        .position(|&b| b == b':')?
        .checked_add(after_key)?;
    let after_colon = colon.checked_add(1)?;
    // Bound the number by the first `,` or `}` after the colon.
    let term = body
        .get(after_colon..)?
        .iter()
        .position(|&b| b == b',' || b == b'}')?
        .checked_add(after_colon)?;
    // Include trailing terminator (`,` or `}`); on-chain _extractId stops at either.
    Some(pos..term.checked_add(1)?)
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
    let body_range = find_response_body_range(recv)?;
    let raw_body = &recv[body_range.clone()];
    let decoded_body = extract_response_body(recv).ok()?;

    // Validate field exists in decoded body
    let _decoded = find_json_snippet_range(&decoded_body, field_name)?;

    // Find in raw body (may include chunk framing)
    let raw_snippet_range = find_json_snippet_range(raw_body, field_name)?;

    let start = body_range.start.checked_add(raw_snippet_range.start)?;
    let end = body_range.start.checked_add(raw_snippet_range.end)?;
    Some(start..end)
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
    {
        let decoded = extract_response_body(recv).ok()?;
        let danchor = decoded
            .windows(anchor_needle.len())
            .position(|w| w == anchor_needle.as_bytes())?;
        let dsub = decoded.get(danchor.checked_add(anchor_needle.len())?..)?;
        if quoted {
            find_json_snippet_range(dsub, field_name)?;
        } else {
            find_json_bare_snippet_range(dsub, field_name)?;
        }
    }

    // The Merkle leaf is over the RAW transcript, so map the range there. (A
    // snippet split across a chunk boundary won't be found contiguously here and
    // fails closed — never mis-resolves.)
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

    // Validate the snippet exists in the decoded body.
    let _decoded = find_json_bare_snippet_range(&decoded_body, field_name)?;
    let raw_snippet_range = find_json_bare_snippet_range(raw_body, field_name)?;

    let start = body_range.start.checked_add(raw_snippet_range.start)?;
    let end = body_range.start.checked_add(raw_snippet_range.end)?;
    Some(start..end)
}

#[cfg(test)]
mod tests {
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
        let body = br#"{"data":[{"text":"@dyaka greet @bob with 1 TST","id":"123"}],"includes":{"users":[{"username":"alice"}]}}"#;
        let range = find_json_field_range(body, "text").unwrap();
        assert_eq!(&body[range], b"@dyaka greet @bob with 1 TST");

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
        // `}`; on-chain _extractId scans digits and stops at it.
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
