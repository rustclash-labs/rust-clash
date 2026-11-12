use std::collections::HashMap;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use url::Url;

use crate::{
    config::{ProxyNodeConfig, REDACTED_SECRET, SkippedProxyEntry},
    error::{ProxyError, Result},
    outbound::{
        ss::crypto::SsCipherKind, vless::encryption::config::parse_client_encryption,
        ws_stream::WsTransportConfig,
    },
};

fn safe_token_preview(raw: &str) -> String {
    let clean: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(24)
        .collect();
    if clean.is_empty() {
        "<invalid>".to_string()
    } else {
        clean
    }
}

/// Scrub proxy share links, subscription URLs/tokens, PQ encryption keys, and inline credentials
/// from any diagnostic, log, or error string so secrets never leak to UI toasts or logs.
pub fn redact_sensitive_text(raw: &str) -> String {
    let mut out = raw.to_string();

    for scheme in [
        "ss://",
        "vless://",
        "anytls://",
        "vmess://",
        "trojan://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "socks5s://",
        "socks5://",
        "socks://",
        "https-proxy://",
        "http-proxy://",
        "https://",
        "http://",
    ] {
        let mut cursor = 0usize;
        while let Some(rel) = out[cursor..].to_ascii_lowercase().find(scheme) {
            let start = cursor + rel;
            let end = out[start..]
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ']' | '>' | ',')
                })
                .map(|len| start + len)
                .unwrap_or(out.len());
            let candidate = &out[start..end];
            if candidate.len() <= scheme.len() {
                cursor = end;
                continue;
            }
            let replacement = if matches!(scheme, "http://" | "https://") {
                redact_url_inline(candidate)
            } else {
                format!("{scheme}{REDACTED_SECRET}")
            };
            out.replace_range(start..end, &replacement);
            cursor = start + replacement.len();
        }
    }

    // Scrub Xray/VLESS PQ encryption/decryption specs if present
    let pq_prefix = "mlkem768x25519plus.";
    let mut cursor = 0usize;
    while let Some(rel) = out[cursor..].find(pq_prefix) {
        let start = cursor + rel;
        let end = out[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '&' | '#' | ')'))
            .map(|len| start + len)
            .unwrap_or(out.len());
        let replacement = format!("{pq_prefix}{REDACTED_SECRET}");
        out.replace_range(start..end, &replacement);
        cursor = start + replacement.len();
    }

    // Scrub sensitive query/kv parameters such as token=..., password=..., secret=..., pbk=...
    for key in [
        "token=",
        "password=",
        "passwd=",
        "secret=",
        "auth=",
        "pbk=",
        "publickey=",
        "uuid=",
    ] {
        let mut k_cursor = 0usize;
        while let Some(rel) = out[k_cursor..].to_ascii_lowercase().find(key) {
            let val_start = k_cursor + rel + key.len();
            let val_end = out[val_start..]
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '&' | '#' | '"' | '\'' | ')' | ';' | ',')
                })
                .map(|len| val_start + len)
                .unwrap_or(out.len());
            out.replace_range(val_start..val_end, REDACTED_SECRET);
            k_cursor = val_start + REDACTED_SECRET.len();
        }
    }

    // Scrub serde quoted string literals (`string "..."`) so malformed scalar inputs never echo
    let marker = "string \"";
    let mut s_cursor = 0usize;
    while let Some(rel) = out[s_cursor..].find(marker) {
        let val_start = s_cursor + rel + marker.len();
        if let Some(end_rel) = out[val_start..].find('"') {
            let val_end = val_start + end_rel;
            out.replace_range(val_start..val_end, REDACTED_SECRET);
            s_cursor = val_start + REDACTED_SECRET.len() + 1;
        } else {
            break;
        }
    }

    out
}

fn redact_url_inline(raw: &str) -> String {
    let Ok(parsed) = Url::parse(raw.trim()) else {
        return "***REDACTED_URL***".to_string();
    };
    let scheme = parsed.scheme();
    let Some(host) = parsed.host_str() else {
        return "***REDACTED_URL***".to_string();
    };
    let port_suffix = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let has_sensitive_tail = !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || (parsed.path() != "/" && !parsed.path().is_empty());
    if has_sensitive_tail {
        format!("{scheme}://{host}{port_suffix}/{REDACTED_SECRET}")
    } else {
        format!("{scheme}://{host}{port_suffix}/")
    }
}

/// Canonical deduplication key for concrete proxy nodes (`(protocol, host, port, credential/params)`).
pub fn proxy_node_dedup_key(node: &ProxyNodeConfig) -> String {
    match node {
        ProxyNodeConfig::Ss {
            server,
            port,
            cipher,
            password,
            ..
        } => format!(
            "ss|{}|{}|{}|{}",
            server.trim().to_ascii_lowercase(),
            port,
            cipher.trim().to_ascii_lowercase(),
            password.trim()
        ),
        ProxyNodeConfig::Vless {
            server,
            port,
            uuid,
            encryption,
            tls,
            servername,
            ..
        } => {
            let ws_sig = node
                .effective_ws_opts()
                .map(|w| {
                    let (p, ed, _) = w.normalized_parts();
                    format!(
                        "ws:{}:{}:{}",
                        p,
                        w.host_header().unwrap_or("").to_ascii_lowercase(),
                        ed
                    )
                })
                .unwrap_or_else(|| "tcp".to_string());
            format!(
                "vless|{}|{}|{}|{}|{}|{}|{}",
                server.trim().to_ascii_lowercase(),
                port,
                uuid,
                encryption.trim(),
                tls,
                servername
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase(),
                ws_sig
            )
        }
        ProxyNodeConfig::Anytls {
            server,
            port,
            password,
            sni,
            ..
        } => format!(
            "anytls|{}|{}|{}|{}",
            server.trim().to_ascii_lowercase(),
            port,
            password.trim(),
            sni.as_deref().unwrap_or("").trim().to_ascii_lowercase()
        ),
        ProxyNodeConfig::Trojan {
            server,
            port,
            password,
            tls,
            sni,
            ..
        } => {
            let ws_sig = node
                .effective_ws_opts()
                .map(|w| {
                    let (p, ed, _) = w.normalized_parts();
                    format!(
                        "ws:{}:{}:{}",
                        p,
                        w.host_header().unwrap_or("").to_ascii_lowercase(),
                        ed
                    )
                })
                .unwrap_or_else(|| "tcp".to_string());
            format!(
                "trojan|{}|{}|{}|{}|{}|{}",
                server.trim().to_ascii_lowercase(),
                port,
                password.trim(),
                tls,
                sni.as_deref().unwrap_or("").trim().to_ascii_lowercase(),
                ws_sig
            )
        }
        ProxyNodeConfig::Socks5 {
            server,
            port,
            username,
            password,
            tls,
            ..
        } => format!(
            "socks5|{}|{}|{}|{}|{}",
            server.trim().to_ascii_lowercase(),
            port,
            username.as_deref().unwrap_or("").trim(),
            password.as_deref().unwrap_or("").trim(),
            tls
        ),
        ProxyNodeConfig::Http {
            server,
            port,
            username,
            password,
            tls,
            ..
        } => format!(
            "http|{}|{}|{}|{}|{}",
            server.trim().to_ascii_lowercase(),
            port,
            username.as_deref().unwrap_or("").trim(),
            password.as_deref().unwrap_or("").trim(),
            tls
        ),
    }
}

/// Parse standard proxy share URIs (`ss://`, `vless://`, `anytls://`, `trojan://`, `socks5://`, `http-proxy://`)
/// into a validated `ProxyNodeConfig`.
pub fn parse_proxy_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Config("proxy URI cannot be empty".into()));
    }

    let lower_prefix: String = trimmed
        .chars()
        .take(20)
        .collect::<String>()
        .to_ascii_lowercase();
    if lower_prefix.starts_with("ss://") {
        let normalized = format!("ss://{}", &trimmed[5..]);
        parse_ss_uri(&normalized)
    } else if lower_prefix.starts_with("vless://") {
        let normalized = format!("vless://{}", &trimmed[8..]);
        parse_vless_uri(&normalized)
    } else if lower_prefix.starts_with("anytls://") {
        let normalized = format!("anytls://{}", &trimmed[9..]);
        parse_anytls_uri(&normalized)
    } else if lower_prefix.starts_with("trojan://") {
        let normalized = format!("trojan://{}", &trimmed[9..]);
        parse_trojan_uri(&normalized)
    } else if lower_prefix.starts_with("socks5s://") {
        parse_socks5_uri(&trimmed[10..], true)
    } else if lower_prefix.starts_with("socks5://") {
        parse_socks5_uri(&trimmed[9..], false)
    } else if lower_prefix.starts_with("socks://") {
        parse_socks5_uri(&trimmed[8..], false)
    } else if lower_prefix.starts_with("https-proxy://") {
        parse_http_proxy_uri(&trimmed[14..], true)
    } else if lower_prefix.starts_with("http-proxy://") {
        parse_http_proxy_uri(&trimmed[13..], false)
    } else if let Some((scheme, _)) = trimmed.split_once("://") {
        let safe_scheme: String = scheme
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            .take(16)
            .collect();
        if safe_scheme.is_empty() {
            Err(ProxyError::Config(
                "unsupported proxy URI scheme (expected ss://, vless://, anytls://, trojan://, socks5://, or http-proxy://)".into(),
            ))
        } else {
            Err(ProxyError::Config(format!(
                "unsupported proxy URI scheme '{safe_scheme}://' (expected ss://, vless://, anytls://, trojan://, socks5://, or http-proxy://)"
            )))
        }
    } else {
        Err(ProxyError::Config(
            "invalid proxy share link format (expected ss://, vless://, anytls://, trojan://, socks5://, or http-proxy://)".into(),
        ))
    }
}

pub fn is_proxy_uri_token(token: &str) -> bool {
    let t = token.trim();
    let Some((scheme, rest)) = t.split_once("://") else {
        return false;
    };
    if scheme.is_empty() || rest.is_empty() {
        return false;
    }
    if !scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return false;
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return false;
    }
    let lc = scheme.to_ascii_lowercase();
    !matches!(lc.as_str(), "http" | "https" | "clash")
}

fn contains_uri_scheme_line(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim();
        !t.is_empty()
            && !t.starts_with('#')
            && ((t.matches("://").count() == 1 && is_proxy_uri_token(t))
                || t.split_whitespace().all(is_proxy_uri_token))
    })
}

/// Decode a Base64-encoded URI subscription list into UTF-8 text if and only if `input` is
/// valid Base64 (standard or URL-safe, padded or unpadded, single-line or MIME multi-line)
/// whose decoded UTF-8 payload contains share URI lines.
pub fn try_decode_base64_uri_list(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || contains_uri_scheme_line(trimmed) {
        return None;
    }
    let bytes = decode_b64_flexible(trimmed)?;
    let decoded = String::from_utf8(bytes).ok()?;
    if contains_uri_scheme_line(&decoded) {
        Some(decoded)
    } else {
        None
    }
}

fn extract_uri_tokens(input: &str) -> Result<Vec<String>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Config(
            "no proxy share links found in empty input".into(),
        ));
    }

    let candidate_owned;
    let candidate = if contains_uri_scheme_line(trimmed) {
        trimmed
    } else if let Some(decoded) = try_decode_base64_uri_list(trimmed) {
        candidate_owned = decoded;
        candidate_owned.as_str()
    } else {
        return Err(ProxyError::Config(
            "input is neither valid proxy share link(s) nor a valid Base64 subscription payload"
                .into(),
        ));
    };

    let mut tokens = Vec::new();
    for line in candidate.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.matches("://").count() > 1 && line.split_whitespace().count() > 1 {
            for token in line.split_whitespace() {
                if !token.is_empty() {
                    tokens.push(token.to_string());
                }
            }
        } else {
            tokens.push(line.to_string());
        }
    }
    if tokens.is_empty() {
        return Err(ProxyError::Config(
            "no valid proxy share links found in input".into(),
        ));
    }
    Ok(tokens)
}

/// Parse one or multiple newline/whitespace-separated URIs (or a Base64-encoded subscription payload) strictly.
pub fn parse_subscription_uris(input: &str) -> Result<Vec<ProxyNodeConfig>> {
    let tokens = extract_uri_tokens(input)?;
    let mut nodes = Vec::with_capacity(tokens.len());
    for token in tokens {
        nodes.push(parse_proxy_uri(&token)?);
    }
    Ok(nodes)
}

fn safe_skipped_uri_metadata(idx: usize, token: &str) -> (String, String) {
    let scheme = token
        .split_once("://")
        .map(|(s, _)| {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                .take(16)
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let fragment_name = token
        .rsplit_once('#')
        .map(|(_, f)| percent_decode_str(f))
        .map(|s| {
            s.trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(48)
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("skipped-{scheme}-{}", idx + 1));

    (fragment_name, scheme)
}

/// Parse one or multiple share URIs (or Base64 URI subscription) with best-effort sanitization:
/// - Skips unsupported/malformed entries into `Vec<SkippedProxyEntry>` when `>= 1` valid node exists.
/// - Fails closed with the redacted error when `0` valid nodes remain!
pub fn parse_subscription_uris_best_effort(
    input: &str,
) -> Result<(Vec<ProxyNodeConfig>, Vec<SkippedProxyEntry>)> {
    let tokens = extract_uri_tokens(input)?;
    let mut nodes = Vec::new();
    let mut skipped = Vec::new();
    let mut first_err: Option<ProxyError> = None;

    for (idx, token) in tokens.iter().enumerate() {
        match parse_proxy_uri(token) {
            Ok(node) => nodes.push(node),
            Err(err) => {
                let redacted_reason = redact_sensitive_text(&err.to_string());
                let (name, protocol) = safe_skipped_uri_metadata(idx, token);
                skipped.push(SkippedProxyEntry {
                    name,
                    protocol,
                    reason: redacted_reason.clone(),
                });
                if first_err.is_none() {
                    first_err = Some(ProxyError::Config(redacted_reason));
                }
            }
        }
    }

    if nodes.is_empty() {
        return Err(first_err.unwrap_or_else(|| {
            ProxyError::Config("no valid proxy share links found in input".into())
        }));
    }

    Ok((nodes, skipped))
}

pub fn export_proxy_uri(node: &ProxyNodeConfig) -> String {
    match node {
        ProxyNodeConfig::Ss {
            name,
            server,
            port,
            cipher,
            password,
            ..
        } => {
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{cipher}:{password}"));
            format!(
                "ss://{userinfo}@{server}:{port}#{}",
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Vless {
            name,
            server,
            port,
            uuid,
            encryption,
            tls,
            servername,
            skip_cert_verify,
            alpn,
            ..
        } => {
            let security = if *tls { "tls" } else { "none" };
            let ws = node.effective_ws_opts();
            let net_type = if ws.is_some() { "ws" } else { "tcp" };
            let mut params = vec![
                format!("type={net_type}"),
                format!("encryption={encryption}"),
                format!("security={security}"),
            ];
            if let Some(ws_cfg) = ws {
                let (clean_path, max_ed, hdr_name) = ws_cfg.normalized_parts();
                params.push(format!("path={}", percent_encode_component(&clean_path)));
                if let Some(h) = ws_cfg.host_header() {
                    params.push(format!("host={}", percent_encode_component(h)));
                }
                if max_ed > 0 {
                    params.push(format!("ed={max_ed}"));
                    if !hdr_name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
                        params.push(format!(
                            "earlyDataHeaderName={}",
                            percent_encode_component(&hdr_name)
                        ));
                    }
                }
            }
            if let Some(sni) = servername {
                params.push(format!("sni={}", percent_encode_component(sni)));
            }
            if !alpn.is_empty() {
                params.push(format!(
                    "alpn={}",
                    percent_encode_component(&alpn.join(","))
                ));
            }
            if *skip_cert_verify {
                params.push("allowInsecure=1".to_string());
            }
            format!(
                "vless://{uuid}@{server}:{port}?{}#{}",
                params.join("&"),
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Anytls {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            alpn,
            ..
        } => {
            let mut params = Vec::new();
            if let Some(sni) = sni {
                params.push(format!("sni={}", percent_encode_component(sni)));
            }
            if !alpn.is_empty() {
                params.push(format!(
                    "alpn={}",
                    percent_encode_component(&alpn.join(","))
                ));
            }
            if *skip_cert_verify {
                params.push("insecure=1".to_string());
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            format!(
                "anytls://{}@{server}:{port}{query}#{}",
                percent_encode_component(password),
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Trojan {
            name,
            server,
            port,
            password,
            tls,
            sni,
            skip_cert_verify,
            alpn,
            udp,
            ..
        } => {
            let mut params = Vec::new();
            if !*tls {
                params.push("security=none".to_string());
            }
            if let Some(sni_val) = sni {
                params.push(format!("sni={}", percent_encode_component(sni_val)));
            }
            if !alpn.is_empty() {
                params.push(format!(
                    "alpn={}",
                    percent_encode_component(&alpn.join(","))
                ));
            }
            if *skip_cert_verify {
                params.push("allowInsecure=1".to_string());
            }
            if !*udp {
                params.push("udp=0".to_string());
            }
            if let Some(ws_cfg) = node.effective_ws_opts() {
                let (clean_path, max_ed, _) = ws_cfg.normalized_parts();
                params.push("type=ws".to_string());
                params.push(format!("path={}", percent_encode_component(&clean_path)));
                if let Some(h) = ws_cfg.host_header() {
                    params.push(format!("host={}", percent_encode_component(h)));
                }
                if max_ed > 0 {
                    params.push(format!("ed={max_ed}"));
                }
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            format!(
                "trojan://{}@{server}:{port}{query}#{}",
                percent_encode_component(password),
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Socks5 {
            name,
            server,
            port,
            username,
            password,
            tls,
            sni,
            skip_cert_verify,
            udp,
        } => {
            let scheme = if *tls { "socks5s" } else { "socks5" };
            let auth = match username.as_deref().filter(|u| !u.is_empty()) {
                Some(u) => format!(
                    "{}:{}@",
                    percent_encode_component(u),
                    percent_encode_component(password.as_deref().unwrap_or(""))
                ),
                None => String::new(),
            };
            let mut params = Vec::new();
            if let Some(s) = sni {
                params.push(format!("sni={}", percent_encode_component(s)));
            }
            if *skip_cert_verify {
                params.push("insecure=1".to_string());
            }
            if !*udp {
                params.push("udp=0".to_string());
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            format!(
                "{scheme}://{auth}{server}:{port}{query}#{}",
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Http {
            name,
            server,
            port,
            username,
            password,
            tls,
            sni,
            skip_cert_verify,
            ..
        } => {
            let scheme = if *tls { "https-proxy" } else { "http-proxy" };
            let auth = match username.as_deref().filter(|u| !u.is_empty()) {
                Some(u) => format!(
                    "{}:{}@",
                    percent_encode_component(u),
                    percent_encode_component(password.as_deref().unwrap_or(""))
                ),
                None => String::new(),
            };
            let mut params = Vec::new();
            if let Some(s) = sni {
                params.push(format!("sni={}", percent_encode_component(s)));
            }
            if *skip_cert_verify {
                params.push("insecure=1".to_string());
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            format!(
                "{scheme}://{auth}{server}:{port}{query}#{}",
                percent_encode_fragment(name)
            )
        }
    }
}

pub(crate) fn decode_b64_flexible(s: &str) -> Option<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    let clean = compact.trim_end_matches('=');
    if clean.is_empty() {
        return None;
    }
    STANDARD_NO_PAD
        .decode(clean)
        .or_else(|_| URL_SAFE_NO_PAD.decode(clean))
        .ok()
}

fn percent_decode_str(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex_str, 16)
        {
            out.push(val);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode_fragment(s: &str) -> String {
    percent_encode_component(s)
}

fn percent_encode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn parse_ss_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let without_scheme = raw.strip_prefix("ss://").unwrap_or(raw);
    let (main_part, fragment) = match without_scheme.split_once('#') {
        Some((m, f)) => (m, Some(percent_decode_str(f))),
        None => (without_scheme, None),
    };
    let (main_part, query) = main_part.split_once('?').unwrap_or((main_part, ""));
    let main_part = main_part.trim_end_matches('/');

    let mut udp = true;
    if !query.is_empty() {
        for pair in query.split('&') {
            if pair.trim().is_empty() {
                continue;
            }
            let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
            let k = percent_decode_str(k_raw).trim().to_ascii_lowercase();
            let v = percent_decode_str(v_raw);
            match k.as_str() {
                "plugin" | "v2ray-plugin" | "obfs" if !v.trim().is_empty() => {
                    return Err(ProxyError::Config(
                        "Shadowsocks SIP003 plugin is not supported (only native AEAD and SS-2022 TCP/UDP are supported)"
                            .into(),
                    ));
                }
                "udp" | "uot" => {
                    if matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false") {
                        udp = false;
                    }
                }
                _ => {}
            }
        }
    }

    let (cipher, password, server, port) = if let Some((userinfo, hostport)) =
        main_part.rsplit_once('@')
    {
        let decoded_user = if userinfo.contains(':') {
            percent_decode_str(userinfo)
        } else {
            let bytes = decode_b64_flexible(userinfo)
                .ok_or_else(|| ProxyError::Config("invalid Base64 userinfo in ss:// URI".into()))?;
            String::from_utf8(bytes)
                .map_err(|_| ProxyError::Config("invalid UTF-8 in ss:// userinfo".into()))?
        };
        let (method, pass) = decoded_user.split_once(':').ok_or_else(|| {
            ProxyError::Config("missing cipher:password separator in ss:// URI".into())
        })?;
        let (host, port) = split_host_port(hostport)?;
        (method.trim().to_string(), pass.to_string(), host, port)
    } else {
        let bytes = decode_b64_flexible(main_part)
            .ok_or_else(|| ProxyError::Config("invalid legacy Base64 ss:// URI".into()))?;
        let full = String::from_utf8(bytes)
            .map_err(|_| ProxyError::Config("invalid UTF-8 in legacy ss:// URI".into()))?;
        let (userinfo, hostport) = full
            .rsplit_once('@')
            .ok_or_else(|| ProxyError::Config("missing '@' in decoded legacy ss:// URI".into()))?;
        let (method, pass) = userinfo
            .split_once(':')
            .ok_or_else(|| ProxyError::Config("missing ':' in decoded legacy ss:// URI".into()))?;
        let (host, port) = split_host_port(hostport)?;
        (method.trim().to_string(), pass.to_string(), host, port)
    };

    if server.trim().is_empty() {
        return Err(ProxyError::Config(
            "missing server host in ss:// URI".into(),
        ));
    }
    if port == 0 {
        return Err(ProxyError::Config(
            "invalid port 0 in ss:// URI (must be 1..=65535)".into(),
        ));
    }
    if password.is_empty() {
        return Err(ProxyError::Config("missing password in ss:// URI".into()));
    }
    let cipher_kind = SsCipherKind::parse(&cipher)
        .map_err(|e| ProxyError::Config(redact_sensitive_text(&e.to_string())))?;
    if password != REDACTED_SECRET {
        cipher_kind
            .master_key(&password)
            .map_err(|e| ProxyError::Config(redact_sensitive_text(&e.to_string())))?;
    }

    let name = fragment
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| format!("SS-{server}:{port}"));
    Ok(ProxyNodeConfig::Ss {
        name,
        server,
        port,
        cipher,
        password,
        udp,
    })
}

fn parse_vless_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let parsed =
        Url::parse(raw).map_err(|_| ProxyError::Config("invalid vless:// URI syntax".into()))?;
    if parsed.password().is_some_and(|p| !p.is_empty()) {
        return Err(ProxyError::Config(
            "invalid vless:// URI userinfo (expected UUID only without ':password')".into(),
        ));
    }
    let uuid_str = percent_decode_str(parsed.username());
    let uuid = uuid::Uuid::parse_str(uuid_str.trim()).map_err(|_| {
        ProxyError::Config("invalid VLESS UUID in vless:// URI (expected 36-char UUID)".into())
    })?;
    let server = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("missing host in vless:// URI".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_string();
    if server.is_empty() {
        return Err(ProxyError::Config("missing host in vless:// URI".into()));
    }
    let port = parsed
        .port()
        .ok_or_else(|| ProxyError::Config("missing port in vless:// URI".into()))?;
    if port == 0 {
        return Err(ProxyError::Config(
            "invalid port 0 in vless:// URI (must be 1..=65535)".into(),
        ));
    }

    let mut encryption = "none".to_string();
    let mut tls = false;
    let mut servername = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut flow = None;
    let mut net_type = "tcp".to_string();
    let mut ws_path: Option<String> = None;
    let mut ws_host: Option<String> = None;
    let mut ws_max_ed: Option<usize> = None;
    let mut ws_ed_hdr: Option<String> = None;
    let mut udp = true;
    let mut remark_fallback = None;

    for (k, v) in parsed.query_pairs() {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "type" | "network" => {
                let net = val_trimmed.to_ascii_lowercase();
                match net.as_str() {
                    "" | "tcp" | "raw" => net_type = "tcp".to_string(),
                    "ws" | "websocket" => net_type = "ws".to_string(),
                    _ => {
                        return Err(ProxyError::Config(format!(
                            "VLESS transport '{}' is not supported (supported: tcp, ws; gRPC, HTTPUpgrade, and QUIC are not supported)",
                            safe_token_preview(val_trimmed)
                        )));
                    }
                }
            }
            "headertype" => {
                let ht = val_trimmed.to_ascii_lowercase();
                if !ht.is_empty() && ht != "none" {
                    return Err(ProxyError::Config(format!(
                        "VLESS headerType '{}' is not supported (only 'none' is supported)",
                        safe_token_preview(val_trimmed)
                    )));
                }
            }
            "security" => {
                let sec = val_trimmed.to_ascii_lowercase();
                match sec.as_str() {
                    "" | "none" => tls = false,
                    "tls" => tls = true,
                    _ => {
                        return Err(ProxyError::Config(format!(
                            "VLESS security '{}' is not supported (REALITY/XTLS are not supported; use security=tls or security=none)",
                            safe_token_preview(val_trimmed)
                        )));
                    }
                }
            }
            "flow" => {
                if !val_trimmed.is_empty() && !val_trimmed.eq_ignore_ascii_case("none") {
                    return Err(ProxyError::Config(format!(
                        "VLESS flow '{}' is not supported (XTLS Vision/flows are not supported; use standard TLS or mlkem768x25519plus encryption)",
                        safe_token_preview(val_trimmed)
                    )));
                }
                flow = None;
            }
            "pbk" | "publickey" | "sid" | "shortid" | "spx" | "spiderx" => {
                if !val_trimmed.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "VLESS REALITY parameter '{}' is not supported (REALITY is not supported)",
                        safe_token_preview(&k)
                    )));
                }
            }
            "path" => {
                if !val_trimmed.is_empty() {
                    ws_path = Some(val_trimmed.to_string());
                }
            }
            "host" | "authority" => {
                if !val_trimmed.is_empty() {
                    ws_host = Some(val_trimmed.to_string());
                }
            }
            "ed" | "maxearlydata" => {
                if !val_trimmed.is_empty() {
                    let parsed_ed: usize = val_trimmed.parse().map_err(|_| {
                        ProxyError::Config(format!(
                            "invalid VLESS early-data size '{}'",
                            safe_token_preview(val_trimmed)
                        ))
                    })?;
                    ws_max_ed = Some(parsed_ed);
                }
            }
            "earlydataheadername" => {
                if !val_trimmed.is_empty() {
                    ws_ed_hdr = Some(val_trimmed.to_string());
                }
            }
            "servicename" | "mode" | "seed" | "quicsecurity" | "key" | "extra" => {
                if !val_trimmed.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "VLESS transport parameter '{}' is not supported (gRPC/HTTPUpgrade/QUIC transports are not supported)",
                        safe_token_preview(&k)
                    )));
                }
            }
            "encryption" => {
                if val_trimmed.is_empty() || val_trimmed.eq_ignore_ascii_case("none") {
                    encryption = "none".to_string();
                } else {
                    if val_trimmed != REDACTED_SECRET {
                        parse_client_encryption(val_trimmed).map_err(|e| {
                            ProxyError::Config(redact_sensitive_text(&e.to_string()))
                        })?;
                    }
                    encryption = val_trimmed.to_string();
                }
            }
            "sni" | "servername" | "peer" => {
                if !val_trimmed.is_empty() {
                    servername = Some(val_trimmed.to_string());
                }
            }
            "allowinsecure" | "insecure" => match val_trimmed.to_ascii_lowercase().as_str() {
                "1" | "true" => skip_cert_verify = true,
                "0" | "false" | "" => skip_cert_verify = false,
                other => {
                    return Err(ProxyError::Config(format!(
                        "invalid VLESS allowInsecure value '{}' (expected 0, 1, true, or false)",
                        safe_token_preview(other)
                    )));
                }
            },
            "alpn" => {
                alpn = val_trimmed
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "udp" => {
                if matches!(val_trimmed.to_ascii_lowercase().as_str(), "0" | "false") {
                    udp = false;
                }
            }
            "fp" | "fingerprint" | "tfo" | "sni_policy" => {
                // Benign client hints emitted by standard subscription panels
            }
            "remark" | "remarks" => {
                if !val_trimmed.is_empty() {
                    remark_fallback = Some(val_trimmed.to_string());
                }
            }
            _ => {
                if !val_trimmed.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "unsupported VLESS query parameter '{}'",
                        safe_token_preview(&k)
                    )));
                }
            }
        }
    }

    let (network, ws_opts) = if net_type == "ws" {
        let mut headers = HashMap::new();
        if let Some(h) = ws_host {
            headers.insert("Host".to_string(), h);
        }
        (
            Some("ws".to_string()),
            Some(WsTransportConfig {
                path: ws_path.unwrap_or_else(|| "/".to_string()),
                headers,
                max_early_data: ws_max_ed,
                early_data_header_name: ws_ed_hdr,
            }),
        )
    } else {
        if ws_max_ed.is_some()
            || ws_ed_hdr.is_some()
            || ws_path.as_deref().is_some_and(|p| p != "/")
        {
            return Err(ProxyError::Config(
                "VLESS WebSocket path/early-data parameters require type=ws".into(),
            ));
        }
        (None, None)
    };

    let name = parsed
        .fragment()
        .map(percent_decode_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(remark_fallback)
        .unwrap_or_else(|| format!("VLESS-{server}:{port}"));

    Ok(ProxyNodeConfig::Vless {
        name,
        server,
        port,
        uuid,
        encryption,
        tls,
        servername,
        skip_cert_verify,
        alpn,
        flow,
        network,
        ws_opts,
        udp,
    })
}

fn parse_trojan_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let parsed =
        Url::parse(raw).map_err(|_| ProxyError::Config("invalid trojan:// URI syntax".into()))?;
    if parsed.password().is_some_and(|p| !p.is_empty()) {
        return Err(ProxyError::Config(
            "invalid trojan:// URI userinfo (percent-encode ':' in password if present)".into(),
        ));
    }
    let password = percent_decode_str(parsed.username());
    if password.trim().is_empty() {
        return Err(ProxyError::Config(
            "missing password in trojan:// URI".into(),
        ));
    }
    let server = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("missing host in trojan:// URI".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_string();
    if server.is_empty() {
        return Err(ProxyError::Config("missing host in trojan:// URI".into()));
    }
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err(ProxyError::Config(
            "invalid port 0 in trojan:// URI (must be 1..=65535)".into(),
        ));
    }

    let mut tls = true;
    let mut sni = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut net_type = "tcp".to_string();
    let mut ws_path: Option<String> = None;
    let mut ws_host: Option<String> = None;
    let mut ws_max_ed: Option<usize> = None;
    let mut ws_ed_hdr: Option<String> = None;
    let mut udp = true;
    let mut remark_fallback = None;

    for (k, v) in parsed.query_pairs() {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "security" => match val_trimmed.to_ascii_lowercase().as_str() {
                "" | "tls" => tls = true,
                "none" => tls = false,
                _ => {
                    return Err(ProxyError::Config(format!(
                        "Trojan security '{}' is not supported (supported: tls, none)",
                        safe_token_preview(val_trimmed)
                    )));
                }
            },
            "type" | "network" => match val_trimmed.to_ascii_lowercase().as_str() {
                "" | "tcp" | "original" => net_type = "tcp".to_string(),
                "ws" | "websocket" => net_type = "ws".to_string(),
                _ => {
                    return Err(ProxyError::Config(format!(
                        "Trojan transport '{}' is not supported (supported: tcp, ws)",
                        safe_token_preview(val_trimmed)
                    )));
                }
            },
            "sni" | "peer" | "servername" => {
                if !val_trimmed.is_empty() {
                    sni = Some(val_trimmed.to_string());
                }
            }
            "allowinsecure" | "insecure" | "skip-cert-verify" => {
                skip_cert_verify =
                    matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "alpn" => {
                alpn = val_trimmed
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "path" => {
                if !val_trimmed.is_empty() {
                    ws_path = Some(val_trimmed.to_string());
                }
            }
            "host" | "authority" => {
                if !val_trimmed.is_empty() {
                    ws_host = Some(val_trimmed.to_string());
                }
            }
            "ed" | "maxearlydata" => {
                if !val_trimmed.is_empty() {
                    let parsed_ed: usize = val_trimmed.parse().map_err(|_| {
                        ProxyError::Config(format!(
                            "invalid Trojan early-data size '{}'",
                            safe_token_preview(val_trimmed)
                        ))
                    })?;
                    ws_max_ed = Some(parsed_ed);
                }
            }
            "earlydataheadername" => {
                if !val_trimmed.is_empty() {
                    ws_ed_hdr = Some(val_trimmed.to_string());
                }
            }
            "udp" => {
                if matches!(val_trimmed.to_ascii_lowercase().as_str(), "0" | "false") {
                    udp = false;
                }
            }
            "pbk" | "publickey" | "sid" | "shortid" | "spx" | "servicename" => {
                if !val_trimmed.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "Trojan parameter '{}' is not supported",
                        safe_token_preview(&k)
                    )));
                }
            }
            "fp" | "fingerprint" | "tfo" | "headertype" => {}
            "remark" | "remarks" if !val_trimmed.is_empty() => {
                remark_fallback = Some(val_trimmed.to_string());
            }
            _ => {}
        }
    }

    let (network, ws_opts) = if net_type == "ws" {
        let mut headers = HashMap::new();
        if let Some(h) = ws_host {
            headers.insert("Host".to_string(), h);
        }
        (
            Some("ws".to_string()),
            Some(WsTransportConfig {
                path: ws_path.unwrap_or_else(|| "/".to_string()),
                headers,
                max_early_data: ws_max_ed,
                early_data_header_name: ws_ed_hdr,
            }),
        )
    } else {
        (None, None)
    };

    let name = parsed
        .fragment()
        .map(percent_decode_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(remark_fallback)
        .unwrap_or_else(|| format!("Trojan-{server}:{port}"));

    Ok(ProxyNodeConfig::Trojan {
        name,
        server,
        port,
        password,
        tls,
        sni,
        skip_cert_verify,
        alpn,
        network,
        ws_opts,
        udp,
    })
}

fn parse_socks5_uri(without_scheme: &str, default_tls: bool) -> Result<ProxyNodeConfig> {
    let (main_part, fragment) = match without_scheme.split_once('#') {
        Some((m, f)) => (m, Some(percent_decode_str(f))),
        None => (without_scheme, None),
    };
    let (main_part, query) = main_part.split_once('?').unwrap_or((main_part, ""));
    let main_part = main_part.trim_end_matches('/');

    let mut tls = default_tls;
    let mut sni = None;
    let mut skip_cert_verify = false;
    let mut udp = true;
    for pair in query.split('&') {
        if pair.trim().is_empty() {
            continue;
        }
        let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode_str(k_raw).trim().to_ascii_lowercase();
        let v = percent_decode_str(v_raw);
        let vt = v.trim();
        match k.as_str() {
            "tls" | "security" => {
                tls = matches!(vt.to_ascii_lowercase().as_str(), "1" | "true" | "tls");
            }
            "sni" | "servername" | "peer" => {
                if !vt.is_empty() {
                    sni = Some(vt.to_string());
                }
            }
            "insecure" | "allowinsecure" | "skip-cert-verify" => {
                skip_cert_verify = matches!(vt.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "udp" => {
                if matches!(vt.to_ascii_lowercase().as_str(), "0" | "false") {
                    udp = false;
                }
            }
            _ => {}
        }
    }

    let (username, password, server, port) =
        if let Some((userinfo, hostport)) = main_part.rsplit_once('@') {
            let (u, p) = if let Some((u_enc, p_enc)) = userinfo.split_once(':') {
                (
                    Some(percent_decode_str(u_enc)),
                    Some(percent_decode_str(p_enc)),
                )
            } else if let Some(decoded) =
                decode_b64_flexible(userinfo).and_then(|b| String::from_utf8(b).ok())
                && let Some((u_dec, p_dec)) = decoded.split_once(':')
            {
                (Some(u_dec.to_string()), Some(p_dec.to_string()))
            } else {
                (Some(percent_decode_str(userinfo)), None)
            };
            let (host, port) = split_host_port(hostport)?;
            (u.filter(|s| !s.is_empty()), p, host, port)
        } else if !main_part.contains(':')
            && let Some(decoded) =
                decode_b64_flexible(main_part).and_then(|b| String::from_utf8(b).ok())
        {
            if let Some((userinfo, hostport)) = decoded.rsplit_once('@') {
                let (u, p) = match userinfo.split_once(':') {
                    Some((u_str, p_str)) => (
                        Some(u_str.to_string()).filter(|s| !s.is_empty()),
                        Some(p_str.to_string()),
                    ),
                    None => (Some(userinfo.to_string()).filter(|s| !s.is_empty()), None),
                };
                let (host, port) = split_host_port(hostport)?;
                (u, p, host, port)
            } else {
                let (host, port) = split_host_port(&decoded)?;
                (None, None, host, port)
            }
        } else {
            let (host, port) = split_host_port(main_part)?;
            (None, None, host, port)
        };

    if server.trim().is_empty() || port == 0 {
        return Err(ProxyError::Config(
            "invalid host or port in socks5:// URI".into(),
        ));
    }
    let name = fragment
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| format!("SOCKS5-{server}:{port}"));

    Ok(ProxyNodeConfig::Socks5 {
        name,
        server,
        port,
        username,
        password,
        tls,
        sni,
        skip_cert_verify,
        udp,
    })
}

fn parse_http_proxy_uri(without_scheme: &str, tls: bool) -> Result<ProxyNodeConfig> {
    let (main_part, fragment) = match without_scheme.split_once('#') {
        Some((m, f)) => (m, Some(percent_decode_str(f))),
        None => (without_scheme, None),
    };
    let (main_part, query) = main_part.split_once('?').unwrap_or((main_part, ""));
    let main_part = main_part.trim_end_matches('/');

    let mut sni = None;
    let mut skip_cert_verify = false;
    for pair in query.split('&') {
        if pair.trim().is_empty() {
            continue;
        }
        let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode_str(k_raw).trim().to_ascii_lowercase();
        let v = percent_decode_str(v_raw);
        let vt = v.trim();
        match k.as_str() {
            "sni" | "servername" | "peer" => {
                if !vt.is_empty() {
                    sni = Some(vt.to_string());
                }
            }
            "insecure" | "allowinsecure" | "skip-cert-verify" => {
                skip_cert_verify = matches!(vt.to_ascii_lowercase().as_str(), "1" | "true");
            }
            _ => {}
        }
    }

    let (username, password, server, port) =
        if let Some((userinfo, hostport)) = main_part.rsplit_once('@') {
            let (u, p) = match userinfo.split_once(':') {
                Some((u_enc, p_enc)) => (
                    Some(percent_decode_str(u_enc)).filter(|s| !s.is_empty()),
                    Some(percent_decode_str(p_enc)),
                ),
                None => (
                    Some(percent_decode_str(userinfo)).filter(|s| !s.is_empty()),
                    None,
                ),
            };
            let (host, port) = split_host_port(hostport)?;
            (u, p, host, port)
        } else {
            let (host, port) = split_host_port(main_part)?;
            (None, None, host, port)
        };

    if server.trim().is_empty() || port == 0 {
        return Err(ProxyError::Config(
            "invalid host or port in http-proxy:// URI".into(),
        ));
    }
    let name = fragment
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| {
            if tls {
                format!("HTTPS-{server}:{port}")
            } else {
                format!("HTTP-{server}:{port}")
            }
        });

    Ok(ProxyNodeConfig::Http {
        name,
        server,
        port,
        username,
        password,
        tls,
        sni,
        skip_cert_verify,
        headers: HashMap::new(),
    })
}

fn parse_anytls_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let parsed =
        Url::parse(raw).map_err(|_| ProxyError::Config("invalid anytls:// URI syntax".into()))?;
    let password = percent_decode_str(parsed.username());
    if password.is_empty() {
        return Err(ProxyError::Config(
            "missing password in anytls:// URI".into(),
        ));
    }
    let server = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("missing host in anytls:// URI".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_string();
    if server.is_empty() {
        return Err(ProxyError::Config("missing host in anytls:// URI".into()));
    }
    let port = parsed
        .port()
        .ok_or_else(|| ProxyError::Config("missing port in anytls:// URI".into()))?;
    if port == 0 {
        return Err(ProxyError::Config(
            "invalid port 0 in anytls:// URI (must be 1..=65535)".into(),
        ));
    }

    let mut sni = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut udp = true;

    for (k, v) in parsed.query_pairs() {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "sni" | "peer" | "servername" => {
                if !val_trimmed.is_empty() {
                    sni = Some(val_trimmed.to_string());
                }
            }
            "insecure" | "allowinsecure" => {
                skip_cert_verify =
                    matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "alpn" => {
                alpn = val_trimmed
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "udp" => {
                if matches!(val_trimmed.to_ascii_lowercase().as_str(), "0" | "false") {
                    udp = false;
                }
            }
            "type" | "network" => {
                let net = val_trimmed.to_ascii_lowercase();
                if !net.is_empty() && net != "tcp" {
                    return Err(ProxyError::Config(format!(
                        "AnyTLS transport '{}' is not supported (only TLS over TCP is supported)",
                        safe_token_preview(val_trimmed)
                    )));
                }
            }
            "fp" | "fingerprint" | "tfo" => {}
            _ => {
                if !val_trimmed.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "unsupported AnyTLS query parameter '{}'",
                        safe_token_preview(&k)
                    )));
                }
            }
        }
    }
    let name = parsed
        .fragment()
        .map(percent_decode_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("AnyTLS-{server}:{port}"));

    Ok(ProxyNodeConfig::Anytls {
        name,
        server,
        port,
        password,
        sni,
        skip_cert_verify,
        alpn,
        idle_session_check_interval: 30,
        idle_session_timeout: 60,
        min_idle_session: 1,
        udp,
    })
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let clean = s.trim_end_matches('/');
    let (host, port_str) = clean
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::Config("missing ':port' in proxy URI host".into()))?;
    let port: u16 = port_str.parse().map_err(|_| {
        ProxyError::Config(format!("invalid port '{}'", safe_token_preview(port_str)))
    })?;
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .trim()
            .to_string(),
        port,
    ))
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::outbound::vless::encryption::{config::XorMode, generate_vless_encryption_pair};

    #[test]
    fn roundtrip_ss_vless_ws_anytls_trojan_socks5_http_uris() {
        let psk = STANDARD.encode([0x42u8; 32]);
        let ss = ProxyNodeConfig::Ss {
            name: "HK SS-2022".into(),
            server: "1.2.3.4".into(),
            port: 8388,
            cipher: "2022-blake3-aes-256-gcm".into(),
            password: psk,
            udp: true,
        };
        let ss_uri = export_proxy_uri(&ss);
        let parsed_ss = parse_proxy_uri(&ss_uri).unwrap();
        assert_eq!(parsed_ss.name(), "HK SS-2022");

        let pq = generate_vless_encryption_pair(XorMode::Native, true, true).unwrap();
        let vless = ProxyNodeConfig::Vless {
            name: "Tokyo VLESS PQ".into(),
            server: "jp.example.com".into(),
            port: 443,
            uuid: uuid::Uuid::new_v4(),
            encryption: pq.encryption,
            tls: false,
            servername: None,
            skip_cert_verify: false,
            alpn: vec![],
            flow: None,
            network: None,
            ws_opts: None,
            udp: true,
        };
        let vless_uri = export_proxy_uri(&vless);
        let parsed_vless = parse_proxy_uri(&vless_uri).unwrap();
        assert_eq!(parsed_vless.name(), "Tokyo VLESS PQ");

        let vless_ws_raw = "vless://12345678-1234-4321-abcd-998877665544@edge.example.com:443?path=%2Fvless%3Fed%3D2048&host=cdn.example.com&encryption=none&security=tls&type=ws#CDN-VLESS-WS";
        let parsed_vless_ws = parse_proxy_uri(vless_ws_raw).unwrap();
        assert_eq!(parsed_vless_ws.protocol_label(), "VLESS+WS");
        let reexported_ws = export_proxy_uri(&parsed_vless_ws);
        let reparsed_ws = parse_proxy_uri(&reexported_ws).unwrap();
        assert_eq!(
            reparsed_ws
                .effective_ws_opts()
                .unwrap()
                .normalized_parts()
                .1,
            2048
        );

        let trojan_raw = "trojan://my%3Asecret%40pass@tj.example.com:443?sni=tj.example.com&type=ws&path=%2Ftj#HK-Trojan";
        let parsed_trojan = parse_proxy_uri(trojan_raw).unwrap();
        assert_eq!(parsed_trojan.name(), "HK-Trojan");
        assert_eq!(parsed_trojan.protocol_label(), "Trojan+WS");
        let reparsed_tj = parse_proxy_uri(&export_proxy_uri(&parsed_trojan)).unwrap();
        assert_eq!(
            proxy_node_dedup_key(&parsed_trojan),
            proxy_node_dedup_key(&reparsed_tj)
        );

        let socks_raw = "socks5://alice:s3cr3t@10.0.0.5:1080#Socks-Relay";
        let parsed_socks = parse_proxy_uri(socks_raw).unwrap();
        assert_eq!(parsed_socks.protocol_label(), "SOCKS5");
        assert_eq!(
            parse_proxy_uri(&export_proxy_uri(&parsed_socks))
                .unwrap()
                .name(),
            "Socks-Relay"
        );

        let http_raw =
            "https-proxy://bob:p%40ss@proxy.example.com:8443?sni=proxy.example.com#HTTPS-Connect";
        let parsed_http = parse_proxy_uri(http_raw).unwrap();
        assert_eq!(parsed_http.protocol_label(), "HTTPS");
        assert_eq!(
            parse_proxy_uri(&export_proxy_uri(&parsed_http))
                .unwrap()
                .name(),
            "HTTPS-Connect"
        );

        let anytls = ProxyNodeConfig::Anytls {
            name: "US AnyTLS v2".into(),
            server: "us.example.com".into(),
            port: 8443,
            password: "secret-password".into(),
            sni: Some("us.example.com".into()),
            skip_cert_verify: true,
            alpn: vec![],
            idle_session_check_interval: 30,
            idle_session_timeout: 60,
            min_idle_session: 1,
            udp: true,
        };
        let anytls_uri = export_proxy_uri(&anytls);
        let parsed_anytls = parse_proxy_uri(&anytls_uri).unwrap();
        assert_eq!(parsed_anytls.name(), "US AnyTLS v2");
    }

    #[test]
    fn strict_rejects_grpc_reality_flow_and_vmess_without_leaking_secrets() {
        let secret_uuid = "12345678-1234-4321-abcd-998877665544";
        let reality_pbk = "SUPER_SECRET_REALITY_PBK_VALUE_XYZ";

        for (uri, expected_substr) in [
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=tls&type=grpc&serviceName=gun#gRPC-Node"
                ),
                "VLESS transport 'grpc' is not supported",
            ),
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=reality&pbk={reality_pbk}&sid=01ab#Reality-Node"
                ),
                "VLESS security 'reality' is not supported",
            ),
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=tls&flow=xtls-rprx-vision#Vision-Node"
                ),
                "VLESS flow 'xtls-rprx-vision' is not supported",
            ),
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=tls&pbk={reality_pbk}#Sneaky-PBK"
                ),
                "VLESS REALITY parameter",
            ),
            (
                "trojan://MY_ULTRA_SECRET_TROJAN_PASS@host.example.com:443?type=grpc&serviceName=gun#Trojan-gRPC"
                    .to_string(),
                "Trojan transport 'grpc' is not supported",
            ),
            (
                "vmess://MY_ULTRA_SECRET_VMESS_PAYLOAD@host.example.com:443#VMess".to_string(),
                "unsupported proxy URI scheme 'vmess://'",
            ),
        ] {
            let err = parse_proxy_uri(&uri).unwrap_err().to_string();
            let safe_err = redact_sensitive_text(&err);
            assert!(
                safe_err.contains(expected_substr),
                "expected '{expected_substr}' in error '{safe_err}'"
            );
            assert!(
                !safe_err.contains(secret_uuid),
                "UUID leaked in error message: {safe_err}"
            );
            assert!(
                !safe_err.contains(reality_pbk),
                "REALITY pbk leaked in error message: {safe_err}"
            );
            assert!(
                !safe_err.contains("MY_ULTRA_SECRET_TROJAN_PASS")
                    && !safe_err.contains("MY_ULTRA_SECRET_VMESS_PAYLOAD"),
                "password leaked in error message: {safe_err}"
            );
        }
    }

    #[test]
    fn mixed_subscription_uris_best_effort_skips_unsupported_and_fails_closed_when_zero_valid() {
        let mixed = "\
trojan://pass123@tj.example.com:443?sni=tj.example.com#HK-Trojan\n\
vmess://SECRET_VMESS_TOKEN@vm.example.com:443#JP-VMess\n\
hy2://SECRET_HY2_PASS@hy2.example.com:443#SG-Hysteria2\n\
socks5://127.0.0.1:1080#Local-Socks\n";
        let (nodes, skipped) = parse_subscription_uris_best_effort(mixed).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0].name, "JP-VMess");
        assert_eq!(skipped[0].protocol, "vmess");
        assert!(!skipped[0].reason.contains("SECRET_VMESS_TOKEN"));
        assert!(!skipped[1].reason.contains("SECRET_HY2_PASS"));

        let all_unsupported = "vmess://SECRET_VMESS_TOKEN@vm.example.com:443#Only-VMess\nhy2://SECRET_HY2_PASS@hy2.example.com:443#Only-Hy2";
        assert!(parse_subscription_uris_best_effort(all_unsupported).is_err());
    }

    #[test]
    fn multiline_and_unpadded_standard_base64_subscriptions_parse_cleanly() {
        let psk = STANDARD.encode([0x11u8; 32]);
        let u1 = format!(
            "ss://{}@10.0.0.1:8388#Node-A",
            STANDARD.encode(format!("2022-blake3-aes-256-gcm:{psk}"))
        );
        let u2 = "anytls://pass123@10.0.0.2:443?sni=sni.example.com#Node-B";
        let bundle = format!("{u1}\n{u2}\n");

        // Wrap at 64 chars with CRLF (MIME style) and strip '=' padding
        let b64_std = STANDARD.encode(bundle.as_bytes());
        let wrapped = b64_std
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        let unpadded = wrapped.trim_end_matches('=');

        let parsed = parse_subscription_uris(unpadded).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name(), "Node-A");
        assert_eq!(parsed[1].name(), "Node-B");
    }
}
