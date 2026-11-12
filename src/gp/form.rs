//! Secret-bearing form data is allocated once and guarded before it is filled.
//! This covers our buffers, not temporary storage inside TLS or XML/JSON parsers.

use super::{GpError, MAX_XML};
use url::form_urlencoded;
use zeroize::Zeroizing;

fn invalid() -> GpError {
    GpError::Protocol("authentication form exceeds resource limit")
}

fn checked_length(current: usize, additional: usize) -> Result<usize, GpError> {
    current
        .checked_add(additional)
        .filter(|length| *length <= MAX_XML)
        .ok_or_else(invalid)
}

fn text_buffer(capacity: usize) -> Result<Zeroizing<String>, GpError> {
    checked_length(0, capacity)?;
    let mut buffer = Zeroizing::new(String::new());
    buffer.try_reserve_exact(capacity).map_err(|_| invalid())?;
    Ok(buffer)
}

fn encoded_length(fields: &[(&str, &str)]) -> Result<usize, GpError> {
    let mut length = 0;
    for (index, (name, value)) in fields.iter().enumerate() {
        length = checked_length(length, usize::from(index != 0) + 1)?;
        for field in [name, value] {
            // Encoding cannot shorten UTF-8 input. Reject huge input before
            // scanning it, then count the exact encoded size without copying.
            checked_length(0, field.len())?;
            for part in form_urlencoded::byte_serialize(field.as_bytes()) {
                length = checked_length(length, part.len())?;
            }
        }
    }
    Ok(length)
}

fn append_form(fields: &[(&str, &str)], buffer: &mut String) {
    // The default UTF-8 encoding borrows each input. The serializer writes
    // directly into the preallocated, already-guarded target.
    form_urlencoded::Serializer::new(buffer)
        .extend_pairs(fields.iter().copied())
        .finish();
}

pub(super) fn encode(fields: &[(&str, &str)]) -> Result<Zeroizing<String>, GpError> {
    let mut output = text_buffer(encoded_length(fields)?)?;
    append_form(fields, &mut output);
    Ok(output)
}

fn tunnel_parts<'a>(path: &'a str, query: &'a str) -> [&'a str; 5] {
    ["GET ", path, "?", query, " HTTP/1.1\r\n\r\n"]
}

fn append_parts(parts: &[&str], output: &mut String) {
    for part in parts {
        output.push_str(part);
    }
}

pub(super) fn tunnel_request(path: &str, query: &str) -> Result<Zeroizing<String>, GpError> {
    if !super::config::valid_tunnel_path(path) || query.len() > MAX_XML {
        return Err(invalid());
    }
    let parts = tunnel_parts(path, query);
    // Both variable inputs are bounded above. Reserve the complete request
    // before copying the secret query: its trailing HTTP suffix must not cause
    // a reallocation after the cookie has entered this buffer.
    let capacity = parts.iter().map(|part| part.len()).sum();
    let mut output = Zeroizing::new(String::new());
    output.try_reserve_exact(capacity).map_err(|_| invalid())?;
    append_parts(&parts, &mut output);
    Ok(output)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn append_decoded(value: &str, buffer: &mut Vec<u8>) {
    let mut bytes = value.as_bytes();
    while let Some((&first, rest)) = bytes.split_first() {
        if first == b'%' && rest.len() >= 2 {
            if let (Some(high), Some(low)) = (hex(rest[0]), hex(rest[1])) {
                buffer.push(high * 16 + low);
                bytes = &rest[2..];
                continue;
            }
        }
        buffer.push(if first == b'+' { b' ' } else { first });
        bytes = rest;
    }
}

/// Visit valid UTF-8 spans and the same replacement characters used by
/// String::from_utf8_lossy, without constructing its unguarded owned Cow.
fn lossy_parts(
    mut bytes: &[u8],
    mut visit: impl FnMut(&str) -> Result<(), GpError>,
) -> Result<(), GpError> {
    loop {
        match std::str::from_utf8(bytes) {
            Ok(valid) => return visit(valid),
            Err(error) => {
                let (valid, invalid_tail) = bytes.split_at(error.valid_up_to());
                // valid_up_to guarantees this prefix is valid; use the safe
                // conversion rather than introducing unchecked UTF-8 access.
                visit(std::str::from_utf8(valid).map_err(|_| invalid())?)?;
                visit("\u{fffd}")?;
                match error.error_len() {
                    Some(length) => bytes = &invalid_tail[length..],
                    None => return Ok(()),
                }
            }
        }
    }
}

fn lossy_length(bytes: &[u8]) -> Result<usize, GpError> {
    let mut length = 0;
    lossy_parts(bytes, |part| {
        length = checked_length(length, part.len())?;
        Ok(())
    })?;
    Ok(length)
}

fn append_lossy(bytes: &[u8], output: &mut String) -> Result<(), GpError> {
    lossy_parts(bytes, |part| {
        output.push_str(part);
        Ok(())
    })
}

/// Decode one login argument, not a query containing multiple fields. Literal
/// ampersands remain literal, '+' means space, valid %HH sequences decode once,
/// and malformed UTF-8 uses the existing lossy replacement behavior. Sentinel
/// values such as "(null)" and "-1" remain the caller's protocol decision.
pub(super) fn decode_argument(value: &str) -> Result<Zeroizing<String>, GpError> {
    checked_length(0, value.len())?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(value.len())
        .map_err(|_| invalid())?;
    append_decoded(value, &mut bytes);
    let mut output = text_buffer(lossy_length(&bytes)?)?;
    append_lossy(&bytes, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_argument(value: &str) -> String {
        // Synthetic data only: the old implementation is the compatibility
        // oracle, including its handling of malformed escapes and UTF-8.
        let encoded = format!("x={}", value.replace('&', "%26"));
        form_urlencoded::parse(encoded.as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned()
    }

    #[test]
    fn encoding_matches_existing_library_for_unicode_escapes_and_empty_fields() {
        for fields in [
            vec![],
            vec![("", "")],
            vec![("user", "user+label"), ("passwd", " a&+=%/雪🔐\0\r\n ")],
            vec![("a&b", "one"), ("a&b", "two"), ("", "tail")],
        ] {
            let expected = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields.iter().copied())
                .finish();
            assert_eq!(&*encode(&fields).unwrap(), &expected);
        }
    }

    #[test]
    fn argument_decoding_matches_all_one_and_two_byte_percent_values() {
        for first in 0_u8..=255 {
            let one = format!("%{first:02X}");
            assert_eq!(&*decode_argument(&one).unwrap(), &legacy_argument(&one));
            for second in 0_u8..=255 {
                let two = format!("%{first:02x}%{second:02X}");
                assert_eq!(&*decode_argument(&two).unwrap(), &legacy_argument(&two));
            }
        }
    }

    #[test]
    fn argument_decoding_preserves_mixed_literals_and_lossy_utf8_semantics() {
        for value in [
            "",
            "&",
            "a&b=c+d",
            "%26+%2b%25",
            "雪+%E9%9B%AA🔐",
            "%",
            "%0",
            "%GG",
            "%1g",
            "%%41",
            "%2+%a&",
            "a%FFb%E2%82c",
            "%ED%A0%80",
            "%F0%90%80%80",
            "%F4%8F%BF%BF",
            "%F4%90%80%80",
            "%F0%9F%94",
            "%C0%AF",
            "雪%FF🔐%80",
            "(null)",
            "%28null%29",
            "-1",
            "%2D1",
            "a%00b%0D%0A",
        ] {
            assert_eq!(&*decode_argument(value).unwrap(), &legacy_argument(value));
        }
    }

    #[test]
    fn guarded_buffers_do_not_reallocate_while_being_filled() {
        let secret = "a&+%雪🔐".repeat(1024);
        let fields = [("passwd", secret.as_str()), ("authcookie", secret.as_str())];
        let mut output = text_buffer(encoded_length(&fields).unwrap()).unwrap();
        let allocation = (output.as_ptr(), output.capacity());
        append_form(&fields, &mut output);
        assert_eq!((output.as_ptr(), output.capacity()), allocation);

        let input = "a+%FF&雪%E2%82%F0%9F%94%90".repeat(1024);
        let mut decoded = Zeroizing::new(Vec::with_capacity(input.len()));
        let allocation = (decoded.as_ptr(), decoded.capacity());
        append_decoded(&input, &mut decoded);
        assert_eq!((decoded.as_ptr(), decoded.capacity()), allocation);
        assert!(decoded.len() <= input.len());

        let expected_length = lossy_length(&decoded).unwrap();
        let mut output = text_buffer(expected_length).unwrap();
        let allocation = (output.as_ptr(), output.capacity());
        append_lossy(&decoded, &mut output).unwrap();
        assert_eq!((output.as_ptr(), output.capacity()), allocation);
        assert_eq!(output.len(), expected_length);
        assert_eq!(&*output, &legacy_argument(&input));
    }

    #[test]
    fn exact_limits_accept_and_expansion_overflow_or_oversize_fail() {
        let at_limit = "a".repeat(MAX_XML - 2);
        assert_eq!(encode(&[("k", &at_limit)]).unwrap().len(), MAX_XML);
        let above_limit = "a".repeat(MAX_XML - 1);
        assert!(encode(&[("k", &above_limit)]).is_err());
        let expanded = "%".repeat(MAX_XML / 3);
        assert!(encode(&[("k", &expanded)]).is_err());

        let at_limit = "a".repeat(MAX_XML);
        assert_eq!(decode_argument(&at_limit).unwrap().len(), MAX_XML);
        let oversize = "a".repeat(MAX_XML + 1);
        for error in [
            encode(&[("k", &oversize)]).unwrap_err(),
            decode_argument(&oversize).unwrap_err(),
            checked_length(usize::MAX, 1).unwrap_err(),
            checked_length(MAX_XML, 1).unwrap_err(),
        ] {
            assert_eq!(
                error.to_string(),
                "GlobalProtect protocol error: authentication form exceeds resource limit"
            );
        }
    }

    #[test]
    fn tunnel_request_keeps_cookie_and_suffix_in_one_fixed_allocation() {
        let path = "/ssl-tunnel-connect.sslvpn";
        for size in [0, 32, 1024, MAX_XML] {
            let query = "s".repeat(size);
            let expected = format!("GET {path}?{query} HTTP/1.1\r\n\r\n");
            assert_eq!(&*tunnel_request(path, &query).unwrap(), &expected);

            let parts = tunnel_parts(path, &query);
            let mut output = Zeroizing::new(String::with_capacity(expected.len()));
            let allocation = (output.as_ptr(), output.capacity());
            append_parts(&parts, &mut output);
            assert_eq!((output.as_ptr(), output.capacity()), allocation);
            assert_eq!(&*output, &expected);
        }
        assert!(tunnel_request(path, &"s".repeat(MAX_XML + 1)).is_err());
        assert!(tunnel_request("/bad\r\npath", "cookie").is_err());
        let longest_path = format!("/{}", "x".repeat(2047));
        assert!(tunnel_request(&longest_path, &"s".repeat(MAX_XML)).is_ok());
        assert!(tunnel_request(&format!("{longest_path}x"), "cookie").is_err());
    }
}
