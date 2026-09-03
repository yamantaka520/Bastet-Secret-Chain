use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn rfc3339(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| ts.to_string())
}

pub fn request_id() -> String {
    let mut b = [0u8; 8];
    // A request id is diagnostics, not security; a zeroed id on RNG failure
    // is acceptable where a failed request is not.
    let _ = getrandom::getrandom(&mut b);
    format!("req_{}", hex::encode(b))
}

/// Encode a decrypted value for JSON: `value` if UTF-8, else `value_base64`.
pub fn value_fields(bytes: &[u8]) -> (Option<String>, Option<String>) {
    use base64::Engine as _;
    match std::str::from_utf8(bytes) {
        Ok(s) => (Some(s.to_string()), None),
        Err(_) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        ),
    }
}

/// Decode `value` / `value_base64` from a request body.
pub fn decode_value(
    value: Option<&str>,
    value_base64: Option<&str>,
) -> Result<Vec<u8>, &'static str> {
    use base64::Engine as _;
    match (value, value_base64) {
        (Some(v), None) => Ok(v.as_bytes().to_vec()),
        (None, Some(b)) => base64::engine::general_purpose::STANDARD
            .decode(b)
            .map_err(|_| "value_base64 is not valid base64"),
        (Some(_), Some(_)) => Err("give value or value_base64, not both"),
        (None, None) => Err("value or value_base64 is required"),
    }
}
