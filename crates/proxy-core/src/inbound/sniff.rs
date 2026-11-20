use std::net::IpAddr;

pub const MAX_SNIFF_BYTES: usize = 16 * 1024;
const MAX_HTTP_SNIFF_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedProtocol {
    Tls,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffOutcome {
    Domain(String),
    NeedMoreBytes,
    NoHostname,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffOutcomeWithProto {
    Domain {
        domain: String,
        protocol: SniffedProtocol,
    },
    NeedMoreBytes,
    NoHostname,
}

const HTTP_METHOD_PREFIXES: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];

/// Validate and normalize an extracted hostname (ASCII lowercase, trailing dot stripped).
/// Rejects empty strings, IP literals, single-label names, malformed DNS labels, and all-numeric TLDs.
pub fn normalize_valid_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 || !trimmed.contains('.') {
        return None;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    let mut last_label = "";
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return None;
        }
        if !bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return None;
        }
        last_label = label;
    }
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(trimmed)
}

/// Inspect leading TCP payload bytes for a TLS `ClientHello` SNI (`server_name` extension)
/// or an HTTP/1.x `Host` header. Immediately returns `NoHostname` for non-TLS/non-HTTP bytes.
pub fn sniff_client_hello_or_http_host(buf: &[u8]) -> SniffOutcome {
    match sniff_tcp_protocol(buf, true, true) {
        SniffOutcomeWithProto::Domain { domain, .. } => SniffOutcome::Domain(domain),
        SniffOutcomeWithProto::NeedMoreBytes => SniffOutcome::NeedMoreBytes,
        SniffOutcomeWithProto::NoHostname => SniffOutcome::NoHostname,
    }
}

/// Protocol-filtered variant of [`sniff_client_hello_or_http_host`] that also reports whether the
/// hostname came from TLS SNI or HTTP `Host`, immediately returning `NoHostname` if the leading
/// bytes cannot match any enabled protocol.
pub fn sniff_tcp_protocol(buf: &[u8], allow_tls: bool, allow_http: bool) -> SniffOutcomeWithProto {
    if !allow_tls && !allow_http {
        return SniffOutcomeWithProto::NoHostname;
    }
    if buf.is_empty() {
        return SniffOutcomeWithProto::NeedMoreBytes;
    }
    if buf[0] == 0x16 {
        if !allow_tls {
            return SniffOutcomeWithProto::NoHostname;
        }
        return match sniff_tls_client_hello(buf) {
            SniffOutcome::Domain(domain) => SniffOutcomeWithProto::Domain {
                domain,
                protocol: SniffedProtocol::Tls,
            },
            SniffOutcome::NeedMoreBytes => SniffOutcomeWithProto::NeedMoreBytes,
            SniffOutcome::NoHostname => SniffOutcomeWithProto::NoHostname,
        };
    }
    if !allow_http {
        return SniffOutcomeWithProto::NoHostname;
    }
    match sniff_http_host(buf) {
        SniffOutcome::Domain(domain) => SniffOutcomeWithProto::Domain {
            domain,
            protocol: SniffedProtocol::Http,
        },
        SniffOutcome::NeedMoreBytes => SniffOutcomeWithProto::NeedMoreBytes,
        SniffOutcome::NoHostname => SniffOutcomeWithProto::NoHostname,
    }
}

fn sniff_tls_client_hello(buf: &[u8]) -> SniffOutcome {
    if buf.len() >= 2 && buf[1] != 0x03 {
        return SniffOutcome::NoHostname;
    }
    if buf.len() >= 3 && buf[2] > 0x04 {
        return SniffOutcome::NoHostname;
    }
    if buf.len() < 5 {
        return SniffOutcome::NeedMoreBytes;
    }

    let mut hs_payload = Vec::new();
    let mut offset = 0usize;
    let mut expected_hs_len: Option<usize> = None;

    while offset < buf.len() {
        if buf[offset] != 0x16 {
            return SniffOutcome::NoHostname;
        }
        if buf.len() - offset < 5 {
            return if buf.len() < MAX_SNIFF_BYTES {
                SniffOutcome::NeedMoreBytes
            } else {
                SniffOutcome::NoHostname
            };
        }
        if buf[offset + 1] != 0x03 || buf[offset + 2] > 0x04 {
            return SniffOutcome::NoHostname;
        }
        let rec_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        if rec_len == 0 || rec_len > MAX_SNIFF_BYTES {
            return SniffOutcome::NoHostname;
        }

        let payload_start = offset + 5;
        let avail = (buf.len() - payload_start).min(rec_len);
        let remaining_cap = MAX_SNIFF_BYTES.saturating_sub(hs_payload.len());
        let take = avail.min(remaining_cap);
        hs_payload.extend_from_slice(&buf[payload_start..payload_start + take]);

        if hs_payload.len() >= 4 {
            if hs_payload[0] != 0x01 {
                return SniffOutcome::NoHostname;
            }
            let hs_len = ((hs_payload[1] as usize) << 16)
                | ((hs_payload[2] as usize) << 8)
                | (hs_payload[3] as usize);
            if !(34..=MAX_SNIFF_BYTES - 4).contains(&hs_len) {
                return SniffOutcome::NoHostname;
            }
            expected_hs_len = Some(hs_len);
            if hs_payload.len() >= 4 + hs_len {
                return parse_client_hello_body(&hs_payload[4..4 + hs_len]);
            }
        }

        if avail < rec_len {
            return if buf.len() < MAX_SNIFF_BYTES {
                SniffOutcome::NeedMoreBytes
            } else {
                SniffOutcome::NoHostname
            };
        }
        offset = payload_start + rec_len;
    }

    if let Some(hs_len) = expected_hs_len
        && hs_payload.len() >= 4 + hs_len
    {
        return parse_client_hello_body(&hs_payload[4..4 + hs_len]);
    }
    if buf.len() < MAX_SNIFF_BYTES {
        SniffOutcome::NeedMoreBytes
    } else {
        SniffOutcome::NoHostname
    }
}

fn parse_client_hello_body(body: &[u8]) -> SniffOutcome {
    // 2B legacy_version + 32B random + at least 1B session_id_len
    if body.len() < 35 {
        return SniffOutcome::NoHostname;
    }
    let mut pos = 34usize;

    let session_id_len = body[pos] as usize;
    pos += 1;
    let Some(next) = pos.checked_add(session_id_len) else {
        return SniffOutcome::NoHostname;
    };
    if next + 2 > body.len() {
        return SniffOutcome::NoHostname;
    }
    pos = next;

    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let Some(next) = pos.checked_add(cipher_suites_len) else {
        return SniffOutcome::NoHostname;
    };
    if next + 1 > body.len() {
        return SniffOutcome::NoHostname;
    }
    pos = next;

    let comp_methods_len = body[pos] as usize;
    pos += 1;
    let Some(next) = pos.checked_add(comp_methods_len) else {
        return SniffOutcome::NoHostname;
    };
    if next > body.len() {
        return SniffOutcome::NoHostname;
    }
    pos = next;

    if pos == body.len() {
        return SniffOutcome::NoHostname;
    }
    if pos + 2 > body.len() {
        return SniffOutcome::NoHostname;
    }
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let Some(exts_end) = pos.checked_add(exts_len) else {
        return SniffOutcome::NoHostname;
    };
    if exts_end > body.len() {
        return SniffOutcome::NoHostname;
    }

    let exts = &body[pos..exts_end];
    let mut ext_pos = 0usize;
    while ext_pos + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[ext_pos], exts[ext_pos + 1]]);
        let ext_len = u16::from_be_bytes([exts[ext_pos + 2], exts[ext_pos + 3]]) as usize;
        ext_pos += 4;
        let Some(ext_end) = ext_pos.checked_add(ext_len) else {
            return SniffOutcome::NoHostname;
        };
        if ext_end > exts.len() {
            return SniffOutcome::NoHostname;
        }
        if ext_type == 0x0000 {
            return parse_sni_extension(&exts[ext_pos..ext_end]);
        }
        ext_pos = ext_end;
    }
    SniffOutcome::NoHostname
}

fn parse_sni_extension(ext_data: &[u8]) -> SniffOutcome {
    if ext_data.len() < 2 {
        return SniffOutcome::NoHostname;
    }
    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    if 2 + list_len > ext_data.len() {
        return SniffOutcome::NoHostname;
    }
    let list = &ext_data[2..2 + list_len];
    let mut pos = 0usize;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
        pos += 3;
        let Some(name_end) = pos.checked_add(name_len) else {
            return SniffOutcome::NoHostname;
        };
        if name_end > list.len() {
            return SniffOutcome::NoHostname;
        }
        if name_type == 0x00 {
            let Ok(raw) = std::str::from_utf8(&list[pos..name_end]) else {
                return SniffOutcome::NoHostname;
            };
            return normalize_valid_hostname(raw)
                .map(SniffOutcome::Domain)
                .unwrap_or(SniffOutcome::NoHostname);
        }
        pos = name_end;
    }
    SniffOutcome::NoHostname
}

fn sniff_http_host(buf: &[u8]) -> SniffOutcome {
    let slice = &buf[..buf.len().min(MAX_HTTP_SNIFF_BYTES)];
    let full_method_match = HTTP_METHOD_PREFIXES.iter().any(|p| slice.starts_with(p));
    if !full_method_match {
        let partial_match =
            slice.len() < 8 && HTTP_METHOD_PREFIXES.iter().any(|p| p.starts_with(slice));
        return if partial_match {
            SniffOutcome::NeedMoreBytes
        } else {
            SniffOutcome::NoHostname
        };
    }

    let mut pos = 0usize;
    let mut line_idx = 0usize;
    while pos < slice.len() {
        let Some(rel_nl) = slice[pos..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let line_bytes = &slice[pos..pos + rel_nl];
        let trimmed_bytes = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
        if line_idx > 0 {
            if trimmed_bytes.is_empty() {
                return SniffOutcome::NoHostname;
            }
            if let Ok(line) = std::str::from_utf8(trimmed_bytes)
                && line.len() >= 5
                && line[..5].eq_ignore_ascii_case("host:")
            {
                let host_val = line[5..].trim();
                let host_only = strip_optional_port(host_val);
                return host_only
                    .and_then(normalize_valid_hostname)
                    .map(SniffOutcome::Domain)
                    .unwrap_or(SniffOutcome::NoHostname);
            }
        }
        line_idx += 1;
        pos += rel_nl + 1;
    }

    if buf.len() < MAX_HTTP_SNIFF_BYTES {
        SniffOutcome::NeedMoreBytes
    } else {
        SniffOutcome::NoHostname
    }
}

fn strip_optional_port(raw_host: &str) -> Option<&str> {
    if raw_host.starts_with('[') || raw_host.contains(']') {
        return None;
    }
    match raw_host.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || port.contains(':') || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(host)
        }
        None => Some(raw_host),
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    pub fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let mut ext_sni = Vec::new();
        let name_bytes = sni.as_bytes();
        let list_len = 1 + 2 + name_bytes.len();
        ext_sni.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(name_bytes);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(0x00); // session id len = 0
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // compression len = 1
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    /// Build a realistic Chrome post-quantum (`X25519MLKEM768` / ECH-sized) TLS `ClientHello`
    /// (~2060B total) where a large `key_share` (`0x0033`) extension precedes the `server_name`
    /// (`0x0000`) extension so the SNI sits beyond the first 1460B TCP MSS segment!
    pub fn build_pq_tls_client_hello(sni: &str, key_share_len: usize) -> Vec<u8> {
        let mut exts = Vec::new();
        // Leading `key_share` extension (simulating 1216B+ ML-KEM-768 + X25519 share + padding)
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        exts.resize(exts.len() + key_share_len, 0x5A);

        // Trailing `server_name` (SNI) extension past byte 1460!
        let name_bytes = sni.as_bytes();
        let list_len = 1 + 2 + name_bytes.len();
        let mut ext_sni = Vec::with_capacity(2 + list_len);
        ext_sni.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(name_bytes);
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xBB; 32]);
        body.push(32); // 32B TLS 1.3 legacy session id
        body.extend_from_slice(&[0xCC; 32]);
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::with_capacity(5 + hs.len());
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_tls_sni_single_and_split_records() {
        let record = test_helpers::build_tls_client_hello("API.GitHub.COM");
        assert_eq!(
            sniff_client_hello_or_http_host(&record),
            SniffOutcome::Domain("api.github.com".to_string())
        );

        // Partial chunk asks for more bytes, never false-fails
        let split = record.len() / 2;
        assert_eq!(
            sniff_client_hello_or_http_host(&record[..split]),
            SniffOutcome::NeedMoreBytes
        );

        // Split the inner ClientHello handshake bytes across two separate TLS 0x16 records
        let hs = &record[5..];
        let hs_split = hs.len() / 2;
        let mut two_records = Vec::new();
        two_records.push(0x16);
        two_records.extend_from_slice(&[0x03, 0x01]);
        two_records.extend_from_slice(&(hs_split as u16).to_be_bytes());
        two_records.extend_from_slice(&hs[..hs_split]);
        two_records.push(0x16);
        two_records.extend_from_slice(&[0x03, 0x03]);
        two_records.extend_from_slice(&((hs.len() - hs_split) as u16).to_be_bytes());
        two_records.extend_from_slice(&hs[hs_split..]);

        assert_eq!(
            sniff_client_hello_or_http_host(&two_records),
            SniffOutcome::Domain("api.github.com".to_string())
        );

        // Chrome ~2060B PQ ClientHello split across 1460B + remainder TCP segments
        let pq_hello = test_helpers::build_pq_tls_client_hello("linux.do", 1950);
        assert!(pq_hello.len() > 2000 && pq_hello.len() < 2200);
        assert_eq!(
            sniff_tcp_protocol(&pq_hello[..1460], true, false),
            SniffOutcomeWithProto::NeedMoreBytes
        );
        assert_eq!(
            sniff_tcp_protocol(&pq_hello, true, false),
            SniffOutcomeWithProto::Domain {
                domain: "linux.do".to_string(),
                protocol: SniffedProtocol::Tls,
            }
        );
    }

    #[test]
    fn sniffs_http_host_with_optional_port_and_rejects_ip_or_binary() {
        let req = b"GET /v1/ping HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(req),
            SniffOutcome::Domain("example.com".to_string())
        );

        // Partial HTTP prefix waits for more bytes
        assert_eq!(
            sniff_client_hello_or_http_host(b"GET"),
            SniffOutcome::NeedMoreBytes
        );
        assert_eq!(
            sniff_client_hello_or_http_host(b"GET / HTTP/1.1\r\nHost: example"),
            SniffOutcome::NeedMoreBytes
        );

        // IP literal in HTTP Host header is rejected
        let ip_host = b"GET / HTTP/1.1\r\nHost: 198.18.1.252:443\r\n\r\n";
        assert_eq!(
            sniff_client_hello_or_http_host(ip_host),
            SniffOutcome::NoHostname
        );

        // Arbitrary binary SSH/non-TLS bytes fail immediately on first chunk
        assert_eq!(
            sniff_client_hello_or_http_host(b"SSH-2.0-OpenSSH_9.6\r\n"),
            SniffOutcome::NoHostname
        );
        assert_eq!(
            sniff_client_hello_or_http_host(&[0x00, 0x01, 0x02, 0x03]),
            SniffOutcome::NoHostname
        );
    }
}
