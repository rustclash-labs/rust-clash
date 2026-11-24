use std::{borrow::Cow, collections::HashMap};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use url::Url;

use crate::{
    config::{ProxyNodeConfig, REDACTED_SECRET, RealityOptsConfig, SkippedProxyEntry},
    error::{ProxyError, Result},
    outbound::{
        hysteria2::parse_hy2_bandwidth_bytes_per_sec,
        quic_common::{PortSpec, QuicCongestionControl, SalamanderObfs},
        ss::crypto::SsCipherKind,
        tuic::TuicUdpRelayMode,
        vless::{
            encryption::config::parse_client_encryption,
            reality::{decode_reality_public_key, decode_reality_short_id},
            vision::VlessVisionFlow,
        },
        vmess::crypto::VmessSecurity,
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

pub(crate) fn trim_bom_and_controls(raw: &str) -> &str {
    raw.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}' || c == '\0')
}

/// A contiguous slice of an input string after structural redaction, mapping each output piece
/// back to its exact byte span `[raw_start, raw_end)` in the original input.
#[derive(Clone, Debug)]
pub(crate) struct RedactPiece {
    pub(crate) raw_start: usize,
    pub(crate) raw_end: usize,
    /// `None` means unchanged literal `&raw[raw_start..raw_end]`;
    /// `Some(text)` means a structured redaction replacement covering `raw_start..raw_end`.
    pub(crate) replacement: Option<String>,
}

impl RedactPiece {
    pub(crate) fn text<'a>(&'a self, raw: &'a str) -> &'a str {
        self.replacement
            .as_deref()
            .unwrap_or(&raw[self.raw_start..self.raw_end])
    }
}

fn apply_piece_edits(
    raw: &str,
    cur: &mut String,
    pieces: &mut Vec<RedactPiece>,
    edits: Vec<(usize, usize, String)>,
) -> bool {
    if edits.is_empty() {
        return false;
    }

    // Phase A: Split literal pieces at every edit boundary strictly inside them.
    // Already-replaced pieces remain atomic so original raw_start..raw_end spans stay exact.
    let mut split_pieces = Vec::with_capacity(pieces.len() + edits.len() * 2);
    let mut boundaries = Vec::with_capacity(edits.len() * 2);
    for &(es, ee, _) in &edits {
        boundaries.push(es);
        if ee != es {
            boundaries.push(ee);
        }
    }
    let mut b_idx = 0usize;
    let mut cur_pos = 0usize;
    for piece in pieces.drain(..) {
        let piece_len = piece.text(raw).len();
        let piece_end = cur_pos + piece_len;
        if piece.replacement.is_some() {
            while b_idx < boundaries.len() && boundaries[b_idx] <= piece_end {
                b_idx += 1;
            }
            split_pieces.push(piece);
        } else {
            let mut sub_raw_start = piece.raw_start;
            let mut sub_cur_start = cur_pos;
            while b_idx < boundaries.len() && boundaries[b_idx] < piece_end {
                let b = boundaries[b_idx];
                b_idx += 1;
                if b > sub_cur_start {
                    let delta = b - sub_cur_start;
                    split_pieces.push(RedactPiece {
                        raw_start: sub_raw_start,
                        raw_end: sub_raw_start + delta,
                        replacement: None,
                    });
                    sub_raw_start += delta;
                    sub_cur_start = b;
                }
            }
            if sub_raw_start < piece.raw_end {
                split_pieces.push(RedactPiece {
                    raw_start: sub_raw_start,
                    raw_end: piece.raw_end,
                    replacement: None,
                });
            }
            while b_idx < boundaries.len() && boundaries[b_idx] == piece_end {
                b_idx += 1;
            }
        }
        cur_pos = piece_end;
    }

    // Phase B: Merge each edit cluster onto its spanned atomic pieces in one linear pass.
    let mut out_pieces = Vec::with_capacity(split_pieces.len() + edits.len());
    let mut edit_iter = edits.into_iter().peekable();
    let mut split_iter = split_pieces.into_iter().peekable();
    let mut p_cur_start = 0usize;

    while let Some(piece) = split_iter.next() {
        let piece_raw_start = piece.raw_start;
        while let Some(&(es, ee, _)) = edit_iter.peek() {
            if es == p_cur_start && ee == p_cur_start {
                let (_, _, rep) = edit_iter.next().unwrap();
                out_pieces.push(RedactPiece {
                    raw_start: piece_raw_start,
                    raw_end: piece_raw_start,
                    replacement: Some(rep),
                });
            } else {
                break;
            }
        }

        let p_len = piece.text(raw).len();
        let p_cur_end = p_cur_start + p_len;

        let starts_in_piece = edit_iter
            .peek()
            .is_some_and(|&(es, ee, _)| es < p_cur_end && (ee > p_cur_start || es > p_cur_start));

        if !starts_in_piece {
            out_pieces.push(piece);
            p_cur_start = p_cur_end;
            continue;
        }

        let cluster_cur_start = p_cur_start;
        let mut cluster_cur_end = p_cur_end;
        let cluster_raw_start = piece.raw_start;
        let mut cluster_raw_end = piece.raw_end;
        let mut cluster_edits = Vec::new();

        while let Some(&(es, ee, _)) = edit_iter.peek() {
            if es >= cluster_cur_end {
                break;
            }
            let edit = edit_iter.next().unwrap();
            cluster_edits.push(edit);
            while ee > cluster_cur_end {
                let Some(next_piece) = split_iter.next() else {
                    break;
                };
                cluster_cur_end += next_piece.text(raw).len();
                cluster_raw_end = next_piece.raw_end;
            }
        }

        let mut merged_text = String::new();
        let mut pos = cluster_cur_start;
        for (es, ee, rep) in cluster_edits {
            merged_text.push_str(&cur[pos..es]);
            merged_text.push_str(&rep);
            pos = ee;
        }
        merged_text.push_str(&cur[pos..cluster_cur_end]);
        out_pieces.push(RedactPiece {
            raw_start: cluster_raw_start,
            raw_end: cluster_raw_end,
            replacement: Some(merged_text),
        });
        p_cur_start = cluster_cur_end;
    }

    for (_, _, rep) in edit_iter {
        out_pieces.push(RedactPiece {
            raw_start: raw.len(),
            raw_end: raw.len(),
            replacement: Some(rep),
        });
    }

    let total_len: usize = out_pieces.iter().map(|p| p.text(raw).len()).sum();
    let mut next_cur = String::with_capacity(total_len);
    for p in &out_pieces {
        next_cur.push_str(p.text(raw));
    }
    *cur = next_cur;
    *pieces = out_pieces;
    true
}

/// Canonical list of network endpoint, DNS transport, and proxy URL schemes shared across
/// inline redaction, audit diffing, and MCP default-mode network metadata scrubbing.
pub const ENDPOINT_URL_SCHEMES: &[&str] = &[
    "https-proxy://",
    "http-proxy://",
    "hysteria2://",
    "wireguard://",
    "hysteria://",
    "socks5s://",
    "socks5h://",
    "juicity://",
    "socks5://",
    "socks4://",
    "trojan://",
    "anytls://",
    "socks://",
    "vless://",
    "vmess://",
    "https://",
    "clash://",
    "snell://",
    "mieru://",
    "http://",
    "quic://",
    "tuic://",
    "sdns://",
    "dhcp://",
    "tls://",
    "doq://",
    "tcp://",
    "udp://",
    "wss://",
    "ssr://",
    "ssd://",
    "hy2://",
    "ssh://",
    "ws://",
    "ss://",
    "wg://",
    "h3://",
];

/// Returns `true` if `scheme` (without `"://"`) is a known endpoint, DNS, or proxy scheme.
pub fn is_known_endpoint_scheme_name(scheme: &str) -> bool {
    ENDPOINT_URL_SCHEMES.iter().any(|candidate| {
        candidate
            .strip_suffix("://")
            .unwrap_or(candidate)
            .eq_ignore_ascii_case(scheme)
    })
}

/// Returns `true` if `s` starts with any canonical endpoint URL scheme (ASCII case-insensitive).
pub fn has_endpoint_url_scheme_prefix(s: &str) -> bool {
    ENDPOINT_URL_SCHEMES.iter().any(|scheme| {
        s.get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    })
}

/// Returns `true` if `s` contains any canonical endpoint URL scheme (ASCII case-insensitive).
pub fn contains_endpoint_url_scheme(s: &str) -> bool {
    if !s.contains("://") {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    ENDPOINT_URL_SCHEMES
        .iter()
        .any(|scheme| lower.contains(scheme))
}

const INLINE_URI_SCHEMES: &[&str] = &[
    "vless://",
    "vmess://",
    "anytls://",
    "hysteria2://",
    "hysteria://",
    "hy2://",
    "trojan://",
    "tuic://",
    "snell://",
    "wireguard://",
    "wg://",
    "wss://",
    "ws://",
    "ss://",
    "ssr://",
    "ssd://",
    "socks5s://",
    "socks5h://",
    "socks5://",
    "socks://",
    "https-proxy://",
    "http-proxy://",
    "clash://",
    "https://",
    "http://",
    "tls://",
    "quic://",
    "h3://",
    "doq://",
];

const WHATWG_BACKSLASH_SCHEMES: &[&str] = &[
    "https:/\\",
    "http:/\\",
    "https:\\\\",
    "http:\\\\",
    "https:\\/",
    "http:\\/",
    "wss:/\\",
    "ws:/\\",
    "wss:\\\\",
    "ws:\\\\",
    "wss:\\/",
    "ws:\\/",
];

const KV_REDACT_KEYS: &[&str] = &[
    "access_token=",
    "api_key=",
    "apikey=",
    "token=",
    "obfs-password=",
    "obfs_password=",
    "obfspassword=",
    "password=",
    "passwd=",
    "secret=",
    "auth_str=",
    "auth-str=",
    "auth=",
    "pbk=",
    "publickey=",
    "public_key=",
    "public-key=",
    "sid=",
    "shortid=",
    "short-id=",
    "short_id=",
    "private_key=",
    "private-key=",
    "psk=",
    "uuid=",
    "signature=",
    "sign=",
    "key=",
];

fn is_opaque_proxy_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "ss://"
            | "ssr://"
            | "ssd://"
            | "vmess://"
            | "vless://"
            | "trojan://"
            | "anytls://"
            | "hysteria2://"
            | "hysteria://"
            | "hy2://"
            | "tuic://"
            | "snell://"
            | "wireguard://"
            | "wg://"
    )
}

fn is_url_redacted_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "http://" | "https://" | "ws://" | "wss://" | "tls://" | "quic://" | "h3://" | "doq://"
    )
}

fn is_whatwg_special_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "http://"
            | "https://"
            | "ws://"
            | "wss://"
            | "https:/\\"
            | "http:/\\"
            | "https:\\\\"
            | "http:\\\\"
            | "https:\\/"
            | "http:\\/"
            | "wss:/\\"
            | "ws:/\\"
            | "wss:\\\\"
            | "ws:\\\\"
            | "wss:\\/"
            | "ws:\\/"
    )
}

fn is_shadowed_scheme_suffix(haystack_lower: &str, scheme: &str, match_start: usize) -> bool {
    let prefix = &haystack_lower[..match_start];
    (scheme == "tls://" && prefix.ends_with("any"))
        || (scheme == "ss://"
            && (prefix.ends_with("vle") || prefix.ends_with("vme") || prefix.ends_with('w')))
}

fn build_whatwg_ws_shadow(s: &str) -> (String, Vec<usize>) {
    let mut shadow_bytes = Vec::with_capacity(s.len());
    let mut map = Vec::with_capacity(s.len());
    for (idx, &b) in s.as_bytes().iter().enumerate() {
        if matches!(b, b'\t' | b'\r' | b'\n') {
            continue;
        }
        shadow_bytes.push(b.to_ascii_lowercase());
        map.push(idx);
    }
    let shadow = String::from_utf8(shadow_bytes)
        .expect("stripping ASCII tab/CR/LF and ASCII-lowercasing preserves UTF-8");
    (shadow, map)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthValueQuote {
    None,
    Plain(char),
    JsonEscaped(char),
}

/// Match an HTTP / JSON-serialized `Authorization` header prefix starting at `match_start`
/// (pointing at `"authorization"` in `lower`), handling optional key quotes before `:`
/// (e.g. `{"Authorization": "Bearer ..."}`, `\"Authorization\": \"Bearer ...\"`,
/// `'Authorization': 'Basic ...'`) and optional enclosing quotes before `Bearer`/`Basic`.
/// Returns `(token_start_offset, enclosing_quote)` on match.
fn match_authorization_header_prefix(
    lower: &str,
    match_start: usize,
) -> Option<(usize, AuthValueQuote)> {
    let bytes = lower.as_bytes();
    let mut p = match_start + "authorization".len();
    if let Some(&q) = bytes.get(p)
        && matches!(q, b'"' | b'\'' | b'`')
    {
        p += 1;
    } else if bytes.get(p) == Some(&b'\\')
        && bytes
            .get(p + 1)
            .is_some_and(|&q| matches!(q, b'"' | b'\'' | b'`'))
    {
        p += 2;
    }
    while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    if bytes.get(p) != Some(&b':') {
        return None;
    }
    p += 1;
    while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    let enclosing_quote = if let Some(&q) = bytes.get(p)
        && matches!(q, b'"' | b'\'' | b'`')
    {
        p += 1;
        AuthValueQuote::Plain(q as char)
    } else if bytes.get(p) == Some(&b'\\')
        && let Some(&q) = bytes.get(p + 1)
        && matches!(q, b'"' | b'\'' | b'`')
    {
        p += 2;
        AuthValueQuote::JsonEscaped(q as char)
    } else {
        AuthValueQuote::None
    };
    if !matches!(enclosing_quote, AuthValueQuote::None) {
        while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
            p += 1;
        }
    }
    let scheme_len = if lower[p..].starts_with("bearer ") || lower[p..].starts_with("bearer\t") {
        "bearer".len()
    } else if lower[p..].starts_with("basic ") || lower[p..].starts_with("basic\t") {
        "basic".len()
    } else {
        return None;
    };
    p += scheme_len;
    while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    Some((p, enclosing_quote))
}

/// Classification of a structural redaction trigger's leading-boundary rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum StructuralTriggerKind {
    /// KV key (`token=`, `key=`, ...) or `Authorization:` header; blocked iff preceded by
    /// ASCII alphanumeric or `'_'`.
    WordBoundary,
    /// Non-nil 36-char hex UUID; blocked iff preceded by an ASCII hex digit.
    Uuid,
    /// Contiguous URL / WHATWG backslash scheme; non-shadowed Pass 1A schemes are never
    /// prefix-blocked.
    Scheme,
}

/// Byte span of a structural redaction trigger in `raw`. Distinct overlapping starts
/// (e.g. `access_token=` and inner `token=`) are preserved so prefix-unblocking never loses
/// nested trigger boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StructuralTriggerSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: StructuralTriggerKind,
    pub(crate) is_prefix_blocked: bool,
}

/// Find byte spans of structural redaction triggers (URL schemes, non-nil UUIDs,
/// `Authorization: Bearer`/`Basic` headers, and sensitive KV keys) in `raw` without requiring
/// leading word boundaries (and without rejecting trailing hex digits on UUIDs), tagging each
/// trigger with its `kind` and whether `raw[start - 1]` actually prefix-blocks it. Used by
/// substring scrubbers to unblock boundary-glued triggers (including nested keys such as
/// `xaccess_token=...` and trailing-hex UUIDs such as `<uuid>aaaa`) in O(N) time without
/// overwriting already-unblocked keywords.
pub(crate) fn find_structural_trigger_spans(raw: &str) -> Vec<StructuralTriggerSpan> {
    if raw.is_empty() {
        return Vec::new();
    }
    let bytes = raw.as_bytes();
    let mut spans = Vec::new();
    let has_colon = raw.contains(':');
    let has_eq = raw.contains('=');
    let lower = if has_colon || has_eq {
        Some(raw.to_ascii_lowercase())
    } else {
        None
    };

    if let Some(ref lower) = lower {
        if lower.contains("://") {
            for &scheme in INLINE_URI_SCHEMES {
                let mut cursor = 0usize;
                while let Some(rel) = lower[cursor..].find(scheme) {
                    let start = cursor + rel;
                    if !is_shadowed_scheme_suffix(lower, scheme, start) {
                        spans.push(StructuralTriggerSpan {
                            start,
                            end: start + scheme.len(),
                            kind: StructuralTriggerKind::Scheme,
                            is_prefix_blocked: false,
                        });
                    }
                    cursor = start + scheme.len();
                }
            }
        }
        if lower.contains(":/\\") || lower.contains(":\\\\") || lower.contains(":\\/") {
            for &scheme in WHATWG_BACKSLASH_SCHEMES {
                let mut cursor = 0usize;
                while let Some(rel) = lower[cursor..].find(scheme) {
                    let start = cursor + rel;
                    spans.push(StructuralTriggerSpan {
                        start,
                        end: start + scheme.len(),
                        kind: StructuralTriggerKind::Scheme,
                        is_prefix_blocked: false,
                    });
                    cursor = start + scheme.len();
                }
            }
        }
        if has_colon && lower.contains("authorization") {
            let mut cursor = 0usize;
            while let Some(rel) = lower[cursor..].find("authorization") {
                let start = cursor + rel;
                if let Some((tok_start, _)) = match_authorization_header_prefix(lower, start) {
                    let is_prefix_blocked = start > 0
                        && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
                    spans.push(StructuralTriggerSpan {
                        start,
                        end: tok_start,
                        kind: StructuralTriggerKind::WordBoundary,
                        is_prefix_blocked,
                    });
                    cursor = tok_start;
                } else {
                    cursor = start + "authorization".len();
                }
            }
        }
        if has_eq {
            for &key in KV_REDACT_KEYS {
                let mut cursor = 0usize;
                while let Some(rel) = lower[cursor..].find(key) {
                    let start = cursor + rel;
                    let is_prefix_blocked = start > 0
                        && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
                    spans.push(StructuralTriggerSpan {
                        start,
                        end: start + key.len(),
                        kind: StructuralTriggerKind::WordBoundary,
                        is_prefix_blocked,
                    });
                    cursor = start + key.len();
                }
            }
        }
    }

    // Non-nil 36-char UUID triggers (ignoring both leading and trailing hex boundaries so
    // `aaaa<uuid>` and `<uuid>aaaa` both unblock when adjacent hex characters are secrets).
    if bytes.len() >= 36 {
        let mut i = 0usize;
        while i + 36 <= bytes.len() {
            if raw.is_char_boundary(i) && raw.is_char_boundary(i + 36) {
                let slice = &raw[i..i + 36];
                let sb = slice.as_bytes();
                let looks_uuid = sb[8] == b'-'
                    && sb[13] == b'-'
                    && sb[18] == b'-'
                    && sb[23] == b'-'
                    && sb
                        .iter()
                        .enumerate()
                        .all(|(idx, b)| matches!(idx, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit());
                if looks_uuid && slice != "00000000-0000-0000-0000-000000000000" {
                    let is_prefix_blocked = i > 0 && bytes[i - 1].is_ascii_hexdigit();
                    spans.push(StructuralTriggerSpan {
                        start: i,
                        end: i + 36,
                        kind: StructuralTriggerKind::Uuid,
                        is_prefix_blocked,
                    });
                    i += 36;
                    continue;
                }
            }
            let ch = raw[i..].chars().next().unwrap();
            i += ch.len_utf8();
        }
    }

    if spans.len() > 1 {
        spans.sort_unstable();
        spans.dedup();
    }
    spans
}

/// Run structural credential/URI/token/UUID redaction on `raw` and return the resulting pieces
/// mapped back to their exact original byte ranges in `raw`.
pub(crate) fn redact_sensitive_text_pieces(raw: &str) -> Vec<RedactPiece> {
    if raw.is_empty() {
        return Vec::new();
    }

    let mut cur = raw.to_string();
    let mut pieces = vec![RedactPiece {
        raw_start: 0,
        raw_end: raw.len(),
        replacement: None,
    }];

    // Pass 1A: Proxy share links, HTTP(S)/WS(S), DoT/DoQ/DoH3 URLs, and WHATWG backslash-scheme URLs
    if cur.contains("://") {
        let mut lower = cur.to_ascii_lowercase();
        for &scheme in INLINE_URI_SCHEMES {
            let opaque_proxy = is_opaque_proxy_scheme(scheme);
            let url_redacted = is_url_redacted_scheme(scheme);
            let special_scheme = is_whatwg_special_scheme(scheme);
            let mut cursor = 0usize;
            let mut horizon = AuthorityAtHorizon::default();
            let mut edits = Vec::new();
            while let Some(rel) = lower[cursor..].find(scheme) {
                let start = cursor + rel;
                if is_shadowed_scheme_suffix(&lower, scheme, start) {
                    cursor = start + scheme.len();
                    continue;
                }
                let end = find_inline_uri_end(
                    &cur,
                    start,
                    scheme.len(),
                    opaque_proxy,
                    special_scheme,
                    &mut horizon,
                );
                let candidate = &cur[start..end];
                if candidate.len() <= scheme.len() {
                    cursor = end;
                    continue;
                }
                let replacement = if url_redacted {
                    redact_url_inline(candidate)
                } else {
                    format!("{scheme}{REDACTED_SECRET}")
                };
                if replacement != candidate {
                    edits.push((start, end, replacement));
                }
                cursor = end;
            }
            if apply_piece_edits(raw, &mut cur, &mut pieces, edits) {
                lower = cur.to_ascii_lowercase();
            }
        }
    }

    if cur.contains(":/\\") || cur.contains(":\\\\") || cur.contains(":\\/") {
        let mut lower = cur.to_ascii_lowercase();
        for &scheme in WHATWG_BACKSLASH_SCHEMES {
            let mut cursor = 0usize;
            let mut horizon = AuthorityAtHorizon::default();
            let mut edits = Vec::new();
            while let Some(rel) = lower[cursor..].find(scheme) {
                let start = cursor + rel;
                let end = find_inline_uri_end(&cur, start, scheme.len(), false, true, &mut horizon);
                if end <= start + scheme.len() {
                    cursor = end;
                    continue;
                }
                edits.push((start, end, "***REDACTED_URL***".to_string()));
                cursor = end;
            }
            if apply_piece_edits(raw, &mut cur, &mut pieces, edits) {
                lower = cur.to_ascii_lowercase();
            }
        }
    }

    // Pass 1B: WHATWG scheme-embedded `\t`/`\r`/`\n` (e.g. `ht\ttps://...`, `https:\t//...`,
    // `https:/\t/...`, `ws\ts://...`, `tl\ts://...`, `s\ts://...`). Zero overhead when no `\t`/`\r`/`\n` exists.
    if cur.bytes().any(|b| matches!(b, b'\t' | b'\r' | b'\n')) {
        let (mut shadow, mut map) = build_whatwg_ws_shadow(&cur);
        if shadow.contains("://")
            || shadow.contains(":/\\")
            || shadow.contains(":\\\\")
            || shadow.contains(":\\/")
        {
            for &scheme in INLINE_URI_SCHEMES
                .iter()
                .chain(WHATWG_BACKSLASH_SCHEMES.iter())
            {
                let opaque_proxy = is_opaque_proxy_scheme(scheme);
                let special_scheme = is_whatwg_special_scheme(scheme);
                let mut s_cursor = 0usize;
                let mut horizon = AuthorityAtHorizon::default();
                let mut edits = Vec::new();
                while let Some(rel) = shadow[s_cursor..].find(scheme) {
                    let s_start = s_cursor + rel;
                    let s_scheme_end = s_start + scheme.len();
                    if is_shadowed_scheme_suffix(&shadow, scheme, s_start) {
                        s_cursor = s_scheme_end;
                        continue;
                    }
                    let orig_start = map[s_start];
                    let orig_after_scheme = map[s_scheme_end - 1] + 1;
                    let orig_scheme_len = orig_after_scheme - orig_start;
                    // Only handle schemes that genuinely contained embedded `\t`/`\r`/`\n`;
                    // contiguous schemes were already processed in Pass 1A.
                    if orig_scheme_len == scheme.len() {
                        s_cursor = s_scheme_end;
                        continue;
                    }
                    // Prevent short 2-3 letter schemes (e.g. `ss://`, `ws://`, `wss://`, `wg://`,
                    // `h3://`, `tls://`) from false-matching the suffix of an English word like `pass:\n//...`.
                    if scheme.len() <= 6
                        && orig_start > 0
                        && cur.as_bytes()[orig_start - 1].is_ascii_alphabetic()
                    {
                        s_cursor = s_scheme_end;
                        continue;
                    }
                    let orig_end = find_inline_uri_end(
                        &cur,
                        orig_start,
                        orig_scheme_len,
                        opaque_proxy,
                        special_scheme,
                        &mut horizon,
                    );
                    if orig_end <= orig_after_scheme {
                        s_cursor = s_scheme_end;
                        continue;
                    }
                    edits.push((orig_start, orig_end, "***REDACTED_URL***".to_string()));
                    s_cursor = s_scheme_end;
                    while s_cursor < map.len() && map[s_cursor] < orig_end {
                        s_cursor += 1;
                    }
                }
                if apply_piece_edits(raw, &mut cur, &mut pieces, edits) {
                    if !cur.bytes().any(|b| matches!(b, b'\t' | b'\r' | b'\n')) {
                        break;
                    }
                    let rebuilt = build_whatwg_ws_shadow(&cur);
                    shadow = rebuilt.0;
                    map = rebuilt.1;
                }
            }
        }
    }

    // Pass 2: Scrub default subscription titles `Sub (<host_or_ip>)` so provider hosts/IPs never leak
    if cur.contains("Sub (") {
        let sub_prefix = "Sub (";
        let mut sub_cursor = 0usize;
        let mut edits = Vec::new();
        while let Some(rel) = cur[sub_cursor..].find(sub_prefix) {
            let inner_start = sub_cursor + rel + sub_prefix.len();
            match cur[inner_start..].find(['\r', '\n', ')']) {
                Some(end_rel) if cur.as_bytes().get(inner_start + end_rel) == Some(&b')') => {
                    let inner_end = inner_start + end_rel;
                    edits.push((inner_start, inner_end, REDACTED_SECRET.to_string()));
                    sub_cursor = inner_end + 1;
                }
                Some(end_rel) => {
                    sub_cursor = inner_start + end_rel + 1;
                }
                None => break,
            }
        }
        apply_piece_edits(raw, &mut cur, &mut pieces, edits);
    }

    // Pass 3: Scrub Xray/VLESS PQ encryption/decryption specs if present
    if cur.contains("mlkem768x25519plus.") {
        let pq_prefix = "mlkem768x25519plus.";
        let mut cursor = 0usize;
        let mut edits = Vec::new();
        while let Some(rel) = cur[cursor..].find(pq_prefix) {
            let start = cursor + rel;
            let pq_slice = &cur[start..];
            let end = pq_slice
                .char_indices()
                .find(|&(idx, c)| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '"' | '\'' | '`' | '&' | '#' | ')' | ']' | '}' | '>' | ',' | ';'
                        )
                        || (c == '\\' && is_escaped_stop_boundary(pq_slice, idx, &['&', '#']))
                })
                .map(|(len, _)| start + len)
                .unwrap_or(cur.len());
            edits.push((start, end, format!("{pq_prefix}{REDACTED_SECRET}")));
            cursor = end;
        }
        apply_piece_edits(raw, &mut cur, &mut pieces, edits);
    }

    // Pass 4: Scrub any non-nil 36-char hex UUID (`8-4-4-4-12`) BEFORE Authorization/KV passes
    // so UUID-glued secrets like `<uuid>token=Secret` unblock immediately in a single pass.
    let uuid_edits = find_non_nil_uuid_edits(&cur);
    apply_piece_edits(raw, &mut cur, &mut pieces, uuid_edits);

    // Pass 5: Scrub HTTP & JSON-serialized `Authorization: Bearer <token>` / `Basic <token>`
    // headers (including quoted `"..."`, `'...'`, `` `...` ``, JSON-escaped `\"...\"` with inner
    // `\\\"` escapes, and JSON object headers like `{"Authorization": "Bearer ..."}`).
    if cur.contains(':') {
        let lower = cur.to_ascii_lowercase();
        if lower.contains("authorization") {
            let mut a_cursor = 0usize;
            let mut parity = LineQuoteParity::default();
            let mut no_close_quote_until = [0usize; 3];
            let mut edits = Vec::new();
            while let Some(rel) = lower[a_cursor..].find("authorization") {
                let match_start = a_cursor + rel;
                if match_start > 0
                    && lower[..match_start]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    a_cursor = match_start + "authorization".len();
                    continue;
                }
                let Some((tok_start, enclosing_quote)) =
                    match_authorization_header_prefix(&lower, match_start)
                else {
                    a_cursor = match_start + "authorization".len();
                    continue;
                };
                let tok_slice = &cur[tok_start..];
                match enclosing_quote {
                    AuthValueQuote::Plain(close_ch) => {
                        let (end_rel, next_rel) = scan_plain_quoted_inner(tok_slice, close_ch);
                        let inner_end = tok_start + end_rel;
                        if inner_end > tok_start {
                            edits.push((tok_start, inner_end, REDACTED_SECRET.to_string()));
                        }
                        a_cursor = (tok_start + next_rel).max(tok_start);
                    }
                    AuthValueQuote::JsonEscaped(close_ch) => {
                        let (end_rel, next_rel) =
                            scan_json_escaped_quoted_inner(tok_slice, close_ch);
                        let inner_end = tok_start + end_rel;
                        if inner_end > tok_start {
                            edits.push((tok_start, inner_end, REDACTED_SECRET.to_string()));
                        }
                        a_cursor = (tok_start + next_rel).max(tok_start);
                    }
                    AuthValueQuote::None => {
                        if let Some(span) = scan_quoted_or_escaped_token(tok_slice) {
                            let inner_start = tok_start + span.inner_start;
                            let inner_end = tok_start + span.inner_end;
                            if inner_end > inner_start {
                                edits.push((inner_start, inner_end, REDACTED_SECRET.to_string()));
                            }
                            a_cursor = tok_start + span.next_offset;
                            continue;
                        }
                        parity.advance_to(cur.as_bytes(), tok_start);
                        let tok_end = scan_unquoted_value_end(
                            &cur,
                            tok_start,
                            &[],
                            parity.open_quotes(),
                            &mut no_close_quote_until,
                        );
                        if tok_end > tok_start {
                            edits.push((tok_start, tok_end, REDACTED_SECRET.to_string()));
                        }
                        a_cursor = tok_end.max(tok_start);
                    }
                }
            }
            apply_piece_edits(raw, &mut cur, &mut pieces, edits);
        }
    }

    // Pass 6: Scrub sensitive query/kv parameters such as token=..., password=..., secret=..., pbk=...
    // including quoted (`"..."`, `'...'`, `` `...` ``) and JSON-escaped (`\"...\"`) values.
    if cur.contains('=') {
        let mut lower = cur.to_ascii_lowercase();
        for &key in KV_REDACT_KEYS {
            let mut k_cursor = 0usize;
            let mut parity = LineQuoteParity::default();
            let mut no_close_quote_until = [0usize; 3];
            let mut edits = Vec::new();
            while let Some(rel) = lower[k_cursor..].find(key) {
                let match_start = k_cursor + rel;
                if match_start > 0
                    && lower[..match_start]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    k_cursor = match_start + key.len();
                    continue;
                }
                let val_start = match_start + key.len();
                let val_slice = &cur[val_start..];
                if let Some(span) = scan_quoted_or_escaped_token(val_slice) {
                    let inner_start = val_start + span.inner_start;
                    let inner_end = val_start + span.inner_end;
                    if inner_end > inner_start {
                        edits.push((inner_start, inner_end, REDACTED_SECRET.to_string()));
                    }
                    k_cursor = val_start + span.next_offset;
                    continue;
                }
                parity.advance_to(cur.as_bytes(), val_start);
                let val_end = scan_unquoted_value_end(
                    &cur,
                    val_start,
                    &['&', '#'],
                    parity.open_quotes(),
                    &mut no_close_quote_until,
                );
                edits.push((val_start, val_end, REDACTED_SECRET.to_string()));
                k_cursor = val_end;
            }
            if apply_piece_edits(raw, &mut cur, &mut pieces, edits) {
                lower = cur.to_ascii_lowercase();
            }
        }
    }

    // Pass 7: Scrub serde quoted string literals (`string "..."`, `string '...'`, ``string `...` ``)
    if cur.contains("string ") {
        for (marker, close_ch) in [("string \"", '"'), ("string '", '\''), ("string `", '`')] {
            let mut s_cursor = 0usize;
            let mut edits = Vec::new();
            while let Some(rel) = cur[s_cursor..].find(marker) {
                let val_start = s_cursor + rel + marker.len();
                if let Some(end_rel) = find_unescaped_close_char(&cur[val_start..], close_ch) {
                    let val_end = val_start + end_rel;
                    edits.push((val_start, val_end, REDACTED_SECRET.to_string()));
                    s_cursor = val_end + close_ch.len_utf8();
                } else {
                    break;
                }
            }
            apply_piece_edits(raw, &mut cur, &mut pieces, edits);
        }
    }

    pieces
}

/// Scrub proxy share links, subscription URLs/tokens, PQ encryption keys, and inline credentials
/// from any diagnostic, log, or error string so secrets never leak to UI toasts or logs.
pub fn redact_sensitive_text(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let pieces = redact_sensitive_text_pieces(raw);
    if pieces.len() == 1 && pieces[0].replacement.is_none() {
        return raw.to_string();
    }
    let total_len: usize = pieces.iter().map(|p| p.text(raw).len()).sum();
    let mut out = String::with_capacity(total_len);
    for p in &pieces {
        out.push_str(p.text(raw));
    }
    out
}

/// Returns `true` iff `bs_rel` is the start of a contiguous run of `'\\'` bytes immediately
/// preceding EOF, whitespace, or a closing delimiter (so left-to-right token scans stop before
/// the entire backslash run in strictly O(N) total time without splitting `\\"`).
pub(crate) fn is_escaped_stop_boundary(slice: &str, bs_rel: usize, extra_delims: &[char]) -> bool {
    if bs_rel > 0 && slice.as_bytes()[bs_rel - 1] == b'\\' {
        return false;
    }
    let after_bs = slice[bs_rel..].trim_start_matches('\\');
    let Some(next) = after_bs.chars().next() else {
        // Trailing backslash(es) at end of input — stop before them.
        return true;
    };
    next.is_whitespace()
        || matches!(next, '"' | '\'' | '`' | ')' | ']' | '}' | '>' | ',' | ';')
        || extra_delims.contains(&next)
}

fn find_unescaped_close_char(slice: &str, close_ch: char) -> Option<usize> {
    let mut consecutive_bs = 0usize;
    for (idx, c) in slice.char_indices() {
        if c == close_ch && consecutive_bs.is_multiple_of(2) {
            return Some(idx);
        }
        if c == '\\' {
            consecutive_bs += 1;
        } else {
            consecutive_bs = 0;
        }
    }
    None
}

/// Result of scanning a quoted (`"..."`, `'...'`, `` `...` ``) or JSON-escaped (`\"...\"`,
/// `\'...\'`, `` \`...\` ``) token value starting at offset 0 of a slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotedTokenSpan {
    /// Byte offset (relative to input slice) where the inner secret value begins.
    pub(crate) inner_start: usize,
    /// Byte offset (relative to input slice) where the inner secret value ends.
    pub(crate) inner_end: usize,
    /// Byte offset (relative to input slice) where scanning should resume after this token
    /// (past any closing quote / escaped quote). Strictly `>= inner_end` and `> 0`.
    pub(crate) next_offset: usize,
}

/// Scan the inner content of a plain quoted value (starting immediately after the opening quote)
/// until the matching unescaped `close_ch`, `\r`/`\n`, or EOF. Returns `(inner_end, next_offset)`.
fn scan_plain_quoted_inner(inner_slice: &str, close_ch: char) -> (usize, usize) {
    let mut consecutive_bs = 0usize;
    for (idx, c) in inner_slice.char_indices() {
        if matches!(c, '\r' | '\n') {
            return (idx, idx);
        }
        if c == close_ch && consecutive_bs.is_multiple_of(2) {
            return (idx, idx + close_ch.len_utf8());
        }
        if c == '\\' {
            consecutive_bs += 1;
        } else {
            consecutive_bs = 0;
        }
    }
    (inner_slice.len(), inner_slice.len())
}

/// Scan the inner content of a JSON-escaped quoted value (starting immediately after `\"`, `\'`,
/// or `` \` ``) in strictly linear O(N) time using exact mod-4 backslash parity:
/// - even backslash runs (`"`, `\\"`, `\\\\"`): outer closing quote; stop before the backslash run
///   so enclosing JSON strings remain syntactically valid;
/// - `k % 4 == 1` (`\"`, `\\\\\"`, ...): closing JSON-escaped quote; stop before `\"` and advance
///   past the quote;
/// - `k % 4 == 3` (`\\\"`, `\\\\\\\"`, ...): escaped inner quote inside JSON; keep scanning.
fn scan_json_escaped_quoted_inner(inner_slice: &str, close_ch: char) -> (usize, usize) {
    let mut consecutive_bs = 0usize;
    for (idx, c) in inner_slice.char_indices() {
        if matches!(c, '\r' | '\n') {
            return (idx, idx);
        }
        if c == close_ch {
            if consecutive_bs.is_multiple_of(2) {
                return (idx - consecutive_bs, idx);
            }
            if consecutive_bs % 4 == 1 {
                return (idx - 1, idx + close_ch.len_utf8());
            }
            consecutive_bs = 0;
            continue;
        }
        if c == '\\' {
            consecutive_bs += 1;
        } else {
            consecutive_bs = 0;
        }
    }
    (inner_slice.len(), inner_slice.len())
}

/// Scan a quoted (`"..."`, `'...'`, `` `...` ``) or JSON-escaped (`\"...\"`, `\'...\'`,
/// `` \`...\` ``) token value beginning at offset 0 of `slice` in strictly linear O(N) time.
/// Returns `None` if `slice` does not start with a quote or JSON-escaped quote.
pub(crate) fn scan_quoted_or_escaped_token(slice: &str) -> Option<QuotedTokenSpan> {
    let bytes = slice.as_bytes();
    let &first = bytes.first()?;
    if matches!(first, b'"' | b'\'' | b'`') {
        let close_ch = first as char;
        let inner_start = 1usize;
        let (end_rel, next_rel) = scan_plain_quoted_inner(&slice[inner_start..], close_ch);
        return Some(QuotedTokenSpan {
            inner_start,
            inner_end: inner_start + end_rel,
            next_offset: inner_start + next_rel,
        });
    }
    if first == b'\\'
        && let Some(&second) = bytes.get(1)
        && matches!(second, b'"' | b'\'' | b'`')
    {
        let close_ch = second as char;
        let inner_start = 2usize;
        let (end_rel, next_rel) = scan_json_escaped_quoted_inner(&slice[inner_start..], close_ch);
        return Some(QuotedTokenSpan {
            inner_start,
            inner_end: inner_start + end_rel,
            next_offset: inner_start + next_rel,
        });
    }
    None
}

/// Monotone per-line quote parity tracker (`[double, single, backtick]`) that resets at `\r`/`\n`
/// and ignores backslash-escaped quotes in strictly O(N) total time.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LineQuoteParity {
    cursor: usize,
    open: [bool; 3],
    consec_bs: usize,
}

impl LineQuoteParity {
    pub(crate) fn advance_to(&mut self, bytes: &[u8], target: usize) {
        let limit = target.min(bytes.len());
        while self.cursor < limit {
            let b = bytes[self.cursor];
            if matches!(b, b'\r' | b'\n') {
                self.open = [false; 3];
                self.consec_bs = 0;
            } else if b == b'\\' {
                self.consec_bs += 1;
            } else {
                if self.consec_bs.is_multiple_of(2) {
                    match b {
                        b'"' => self.open[0] = !self.open[0],
                        b'\'' => self.open[1] = !self.open[1],
                        b'`' => self.open[2] = !self.open[2],
                        _ => {}
                    }
                }
                self.consec_bs = 0;
            }
            self.cursor += 1;
        }
    }

    pub(crate) fn open_quotes(&self) -> [bool; 3] {
        self.open
    }
}

/// Scan an unquoted Pass 5 (`Authorization:`) or Pass 6 (`key=val`) value starting at `val_start`
/// in `cur`. Stops at ASCII whitespace, closing structural delimiters, `extra_delims`, escaped
/// stop boundaries, or an enclosing/unmatched quote. When no enclosing outer quote of type `q` is
/// open on the current line (`!open_quotes[qi]`), an inline paired quote span `q...q` inside the
/// same non-delimited token (e.g. `token=foo_xkey="a"-Tail`) is consumed as part of the value so
/// glued tails after the inline quote cannot leak. Backed by `no_close_quote_until` for O(N) time.
fn scan_unquoted_value_end(
    cur: &str,
    val_start: usize,
    extra_delims: &[char],
    open_quotes: [bool; 3],
    no_close_quote_until: &mut [usize; 3],
) -> usize {
    let val_slice = &cur[val_start..];
    let mut pos = 0usize;
    while pos < val_slice.len() {
        let c = val_slice[pos..].chars().next().unwrap();
        if c.is_whitespace()
            || matches!(c, ')' | ']' | '}' | '>' | ';' | ',')
            || extra_delims.contains(&c)
            || (c == '\\' && is_escaped_stop_boundary(val_slice, pos, extra_delims))
        {
            return val_start + pos;
        }
        if let Some(qi) = match c {
            '"' => Some(0usize),
            '\'' => Some(1usize),
            '`' => Some(2usize),
            _ => None,
        } {
            let abs_quote = val_start + pos;
            if open_quotes[qi] || abs_quote < no_close_quote_until[qi] {
                return abs_quote;
            }
            let after_open = pos + c.len_utf8();
            let mut inner_bs = 0usize;
            let mut found_close: Option<usize> = None;
            let mut scan_stop_rel = val_slice.len();
            for (rel, ic) in val_slice[after_open..].char_indices() {
                let cur_rel = after_open + rel;
                if ic.is_whitespace()
                    || matches!(ic, ')' | ']' | '}' | '>' | ';' | ',')
                    || extra_delims.contains(&ic)
                {
                    scan_stop_rel = cur_rel;
                    break;
                }
                if ic == c && inner_bs.is_multiple_of(2) {
                    found_close = Some(cur_rel + ic.len_utf8());
                    break;
                }
                if ic == '\\' {
                    inner_bs += 1;
                } else {
                    inner_bs = 0;
                }
            }
            if let Some(resume_rel) = found_close {
                pos = resume_rel;
                continue;
            }
            no_close_quote_until[qi] = no_close_quote_until[qi].max(val_start + scan_stop_rel);
            return abs_quote;
        }
        pos += c.len_utf8();
    }
    cur.len()
}

/// Compute the byte offset in `raw` where a `WordBoundary` trigger's value token terminates,
/// using the exact same Pass 5 (`Authorization:`) and Pass 6 (KV) rules as
/// `redact_sensitive_text_pieces`.
pub(crate) fn scan_word_boundary_trigger_value_end(
    raw: &str,
    lower: &str,
    trigger: StructuralTriggerSpan,
    open_quotes: [bool; 3],
    no_close_quote_until: &mut [usize; 3],
) -> usize {
    let bytes = raw.as_bytes();
    if trigger.end > 0 && bytes[trigger.end - 1] == b'=' {
        let val_slice = &raw[trigger.end..];
        if let Some(span) = scan_quoted_or_escaped_token(val_slice) {
            return trigger.end + span.next_offset;
        }
        return scan_unquoted_value_end(
            raw,
            trigger.end,
            &['&', '#'],
            open_quotes,
            no_close_quote_until,
        );
    }
    if let Some((tok_start, enclosing_quote)) =
        match_authorization_header_prefix(lower, trigger.start)
    {
        let tok_slice = &raw[tok_start..];
        return match enclosing_quote {
            AuthValueQuote::Plain(close_ch) => {
                let (_, next_rel) = scan_plain_quoted_inner(tok_slice, close_ch);
                (tok_start + next_rel).max(tok_start)
            }
            AuthValueQuote::JsonEscaped(close_ch) => {
                let (_, next_rel) = scan_json_escaped_quoted_inner(tok_slice, close_ch);
                (tok_start + next_rel).max(tok_start)
            }
            AuthValueQuote::None => {
                if let Some(span) = scan_quoted_or_escaped_token(tok_slice) {
                    tok_start + span.next_offset
                } else {
                    scan_unquoted_value_end(raw, tok_start, &[], open_quotes, no_close_quote_until)
                }
            }
        };
    }
    trigger.end
}

fn is_hard_escaped_stop_excluding_whatwg_ws(slice: &str, bs_rel: usize) -> bool {
    if bs_rel > 0 && slice.as_bytes()[bs_rel - 1] == b'\\' {
        return false;
    }
    let after_bs = slice[bs_rel..].trim_start_matches('\\');
    let Some(next) = after_bs.chars().next() else {
        return true;
    };
    (next.is_whitespace() && !matches!(next, '\t' | '\r' | '\n'))
        || matches!(next, '"' | '\'' | '`' | ')' | ']' | '}' | '>' | ',' | ';')
}

fn is_hard_uri_stop(slice: &str, pos: usize, c: char) -> bool {
    (c.is_whitespace() && !matches!(c, '\t' | '\r' | '\n'))
        || matches!(c, '"' | '\'' | '`' | ')' | ']' | '}' | '>' | ',' | ';')
        || (c == '\\' && is_hard_escaped_stop_excluding_whatwg_ws(slice, pos))
}

fn next_uri_token_end(slice: &str, start: usize, mut in_ipv6: bool) -> usize {
    for (offset, c) in slice[start..].char_indices() {
        let pos = start + offset;
        if c == ']' && in_ipv6 {
            in_ipv6 = false;
            continue;
        }
        if c.is_whitespace()
            || matches!(c, '"' | '\'' | '`' | ')' | ']' | '}' | '>' | ',' | ';')
            || (c == '\\' && is_hard_escaped_stop_excluding_whatwg_ws(slice, pos))
        {
            return pos;
        }
    }
    slice.len()
}

fn has_scheme_separator_with_prefix(tok: &str, sep: &str) -> bool {
    let bytes = tok.as_bytes();
    let Some(idx) = tok.find(sep) else {
        return false;
    };
    if idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric() {
        return false;
    }
    // A path, backslash-path, query, fragment, or `@` continuation (e.g. `/xhttps://...`,
    // `?next=https://...`) is a URL tail rather than a separate scheme column; treating it as a
    // tail preserves both complete redaction of redirect paths and strict Pass 1 == Pass 2
    // idempotency.
    !tok[..idx]
        .bytes()
        .any(|b| matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@'))
}

/// Returns `true` if `tok` starts a new URL or WHATWG backslash scheme column (`://`, `:/\`,
/// `:\\`, `:\\/` preceded by a scheme prefix without path/query/fragment delimiters) or an
/// already-redacted `***REDACTED_URL***` column (preventing Pass-2 re-bridging on TSV rows like
/// `https://a.com/\thttps://\tc/secret`).
fn is_scheme_token(tok: &str) -> bool {
    tok.starts_with("***REDACTED_URL***")
        || has_scheme_separator_with_prefix(tok, "://")
        || has_scheme_separator_with_prefix(tok, ":/\\")
        || has_scheme_separator_with_prefix(tok, ":\\\\")
        || has_scheme_separator_with_prefix(tok, ":\\/")
}

/// Returns `true` when `tok` looks like a separate logfmt/TSV `key=value` column (contains `=`
/// before any URL path/query/fragment delimiter `/`, `?`, `#`).
fn token_is_log_kv_field(tok: &str) -> bool {
    let head = tok.split(['/', '?', '#']).next().unwrap_or(tok);
    head.contains('=')
}

/// Returns `true` when `tok` contains a `'\\'` followed by at least one non-backslash byte
/// (matching WHATWG special-scheme `\` path separators like `dns.io\Secret` without matching
/// standalone trailing `\`/`\\` in TSV columns or JSON escapes).
fn has_non_trailing_backslash(tok: &str) -> bool {
    tok.find('\\')
        .is_some_and(|i| tok[i + 1..].bytes().any(|b| b != b'\\'))
}

fn is_ipv6_chunk_chars(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
}

fn peek_ipv6_colon_continuation(rest: &str, from: usize) -> bool {
    let bytes = rest.as_bytes();
    let mut ws_end = from;
    while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r' | b'\n') {
        ws_end += 1;
    }
    if ws_end == from || ws_end >= bytes.len() {
        return false;
    }
    let tok_end = next_uri_token_end(rest, ws_end, true);
    let after = &rest[ws_end..tok_end];
    if after.is_empty() {
        return false;
    }
    let ip_chunk = after.split(']').next().unwrap_or(after);
    if is_scheme_token(ip_chunk) {
        return false;
    }
    after.starts_with(':') || (ip_chunk.contains(':') && is_ipv6_chunk_chars(ip_chunk))
}

/// Per-pass monotonic lookahead cache for `find_last_authority_at`, keyed by `in_ipv6` state
/// (`0 = outside [...]`, `1 = inside [...]`). Each range `(lo, hi)` certifies that scanning
/// forward in `cur` from any byte position `p` with `lo <= p < hi` in that state terminates at or
/// before `hi` without encountering any `'@'` byte. Because `in_ipv6 == false` visits a subset of
/// bytes of `in_ipv6 == true`, every certified state-1 range also certifies state 0.
#[derive(Default, Clone, Copy)]
struct AuthorityAtHorizon {
    no_at_ranges: [(usize, usize); 2],
}

impl AuthorityAtHorizon {
    fn certified_no_at_end(&self, in_ipv6: bool, pos: usize) -> Option<usize> {
        let (lo, hi) = self.no_at_ranges[in_ipv6 as usize];
        if pos >= lo && pos < hi {
            return Some(hi);
        }
        if !in_ipv6 {
            let (lo1, hi1) = self.no_at_ranges[1];
            if pos >= lo1 && pos < hi1 {
                return Some(hi1);
            }
        }
        None
    }

    fn record(&mut self, in_ipv6: bool, lo: usize, hi: usize) {
        if lo >= hi {
            return;
        }
        let slot = &mut self.no_at_ranges[in_ipv6 as usize];
        if hi > slot.1 {
            if lo <= slot.1 && slot.0 < slot.1 {
                slot.0 = slot.0.min(lo);
                slot.1 = hi;
            } else {
                *slot = (lo, hi);
            }
        } else if lo < slot.0 && hi >= slot.0 {
            slot.0 = lo;
        }
    }
}

/// Monotonic authority `@`-lookahead in `cur` byte coordinates that skips ASCII `\t`/`\r`/`\n`
/// runs (stopping at any hard URI stop, `?`, `#`, unescaped `/`, or a new scheme token).
/// Backed by `AuthorityAtHorizon`, every byte in `cur` is scanned at most once per `in_ipv6` state
/// across an entire pass, mathematically guaranteeing strict O(N) total time on all inputs
/// (including repeated `https:\\a\t`, `https:\t\\a\t`, `https:\t\\[a]\t`, and `https:\t\\[@]\t`).
fn find_last_authority_at(
    cur: &str,
    abs_from: usize,
    start_in_ipv6: bool,
    horizon: &mut AuthorityAtHorizon,
) -> Option<usize> {
    if horizon
        .certified_no_at_end(start_in_ipv6, abs_from)
        .is_some()
    {
        return None;
    }

    let bytes = cur.as_bytes();
    let mut pos = abs_from;
    let mut in_ipv6 = start_in_ipv6;
    let mut last_at: Option<usize> = None;
    let mut tail_start = abs_from;
    let mut tail_started_in_ipv6 = start_in_ipv6;
    let mut tail_ipv6_end: Option<usize> = None;

    while pos < bytes.len() {
        if let Some(cert_end) = horizon.certified_no_at_end(in_ipv6, pos) {
            if tail_started_in_ipv6 && tail_ipv6_end.is_none() && in_ipv6 {
                tail_ipv6_end = Some(cert_end);
            }
            pos = cert_end;
            break;
        }
        if matches!(bytes[pos], b'\t' | b'\r' | b'\n') {
            while pos < bytes.len() && matches!(bytes[pos], b'\t' | b'\r' | b'\n') {
                pos += 1;
            }
            if pos >= bytes.len() {
                break;
            }
            if bytes[pos] == b']' {
                if !in_ipv6 {
                    break;
                }
                let after_rb = pos + 1;
                let tok_end = next_uri_token_end(cur, after_rb, false);
                if is_scheme_token(&cur[after_rb..tok_end]) {
                    break;
                }
                continue;
            }
            let tok_end = next_uri_token_end(cur, pos, false);
            if tok_end == pos || is_scheme_token(&cur[pos..tok_end]) {
                break;
            }
            continue;
        }
        let c = cur[pos..].chars().next().unwrap();
        if c == '[' {
            in_ipv6 = true;
            pos += 1;
            continue;
        }
        if c == ']' && in_ipv6 {
            in_ipv6 = false;
            if tail_started_in_ipv6 && tail_ipv6_end.is_none() {
                tail_ipv6_end = Some(pos);
            }
            pos += 1;
            continue;
        }
        if is_hard_uri_stop(cur, pos, c) || matches!(c, '?' | '#') {
            break;
        }
        if c == '/' {
            if !(pos > 0 && bytes[pos - 1] == b'\\') {
                break;
            }
        } else if c == '@' {
            last_at = Some(pos);
            tail_start = pos + 1;
            tail_started_in_ipv6 = in_ipv6;
            tail_ipv6_end = None;
        }
        pos += c.len_utf8();
    }

    let stop = pos;
    if tail_start < stop {
        horizon.record(false, tail_start, stop);
        if tail_started_in_ipv6 {
            let ipv6_stop = tail_ipv6_end.unwrap_or(stop);
            if tail_start < ipv6_stop {
                horizon.record(true, tail_start, ipv6_stop);
            }
        }
    }
    last_at
}

/// Returns `true` when `next_tok` immediately following a leading `\t`/`\r`/`\n` prefix after
/// `scheme://` is a bare IPv4/IPv6/SocketAddr host literal (including bracketed IPv6 split by
/// WHATWG `\t`/`\r`/`\n` before or after the first `:`, IP/IPv6 + `:` before `\t`/`\r` + port,
/// and mid-dot IPv4 split by `\t`/`\r`), while rejecting plain prose or non-IP bracketed
/// timestamps like `[10:00:00]`.
fn is_leading_whatwg_ip_token(
    rest: &str,
    prefix_end: usize,
    next_tok: &str,
    tok_end: usize,
) -> bool {
    let bytes = rest.as_bytes();
    if next_tok.parse::<std::net::IpAddr>().is_ok()
        || next_tok.parse::<std::net::SocketAddr>().is_ok()
    {
        return true;
    }
    if let Some(host_only) = next_tok.strip_suffix(':') {
        let is_ip_host = host_only.parse::<std::net::Ipv4Addr>().is_ok()
            || host_only
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .is_some_and(|v6| v6.parse::<std::net::Ipv6Addr>().is_ok());
        if is_ip_host {
            let mut ws_end = tok_end;
            while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r') {
                ws_end += 1;
            }
            if ws_end > tok_end && bytes.get(ws_end).is_some_and(u8::is_ascii_digit) {
                return true;
            }
        }
    }
    if let Some(inner) = next_tok.strip_prefix('[') {
        if let Some(bracketed) = inner.strip_suffix(']') {
            return bracketed.parse::<std::net::Ipv6Addr>().is_ok();
        }
        if !inner.is_empty() && !inner.contains(']') {
            if inner.contains(':') && is_ipv6_chunk_chars(inner) {
                return true;
            }
            if inner.bytes().all(|b| b.is_ascii_hexdigit()) {
                return peek_ipv6_colon_continuation(rest, tok_end);
            }
        }
        if inner.is_empty() {
            let mut ws_end = prefix_end + 1;
            while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r' | b'\n') {
                ws_end += 1;
            }
            if ws_end > prefix_end + 1 && ws_end < bytes.len() {
                let tok2_end = next_uri_token_end(rest, ws_end, true);
                let after_lb = &rest[ws_end..tok2_end];
                let ip_chunk = after_lb.split(']').next().unwrap_or(after_lb);
                if !after_lb.is_empty() && !is_scheme_token(ip_chunk) {
                    if ip_chunk.contains(':') && is_ipv6_chunk_chars(ip_chunk) {
                        return true;
                    }
                    if !after_lb.contains(']')
                        && !ip_chunk.is_empty()
                        && ip_chunk.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return peek_ipv6_colon_continuation(rest, tok2_end);
                    }
                }
            }
        }
        return false;
    }
    if next_tok.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && next_tok.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        let mut ws_end = tok_end;
        while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r') {
            ws_end += 1;
        }
        if ws_end > tok_end && ws_end < bytes.len() {
            let tok2_end = next_uri_token_end(rest, ws_end, false);
            let next_tok2 = &rest[ws_end..tok2_end];
            if !next_tok2.is_empty()
                && !is_scheme_token(next_tok2)
                && !token_is_log_kv_field(next_tok2)
            {
                let next_b = next_tok2.as_bytes()[0];
                if next_tok.ends_with('.') && next_b.is_ascii_digit() {
                    return true;
                }
                if !next_tok.ends_with('.')
                    && next_b == b'.'
                    && next_tok2.as_bytes().get(1).is_some_and(u8::is_ascii_digit)
                {
                    return true;
                }
            }
        }
    }
    false
}

#[derive(Clone, Copy)]
struct BsBridgeState {
    in_authority: bool,
    in_ipv6_host: bool,
    in_non_root_path: bool,
}

/// Returns `true` when a backslash run starting at `bs_pos` (relative to `abs_base`) immediately
/// precedes WHATWG `\t`/`\r` (or `\n` with `@` ahead in authority, or `\n` in a non-root path
/// symmetric with `/`) and bridges into a genuine URL continuation rather than a hard stop, JSON
/// quote, scheme token, comment `#`, or root/authority logfmt KV.
fn can_bridge_whatwg_bs_ws(
    cur: &str,
    abs_base: usize,
    bs_pos: usize,
    state: BsBridgeState,
    auth_at_pos: &mut Option<Option<usize>>,
    horizon: &mut AuthorityAtHorizon,
) -> bool {
    let rest = &cur[abs_base..];
    let bytes = rest.as_bytes();
    let after_bs = rest[bs_pos..].trim_start_matches('\\');
    let Some(&first_after) = after_bs.as_bytes().first() else {
        return false;
    };
    if !matches!(first_after, b'\t' | b'\r' | b'\n') {
        return false;
    }
    let has_auth_at = state.in_authority
        && match *auth_at_pos {
            Some(cached) => cached.is_some_and(|at| at > bs_pos),
            None => {
                let computed =
                    find_last_authority_at(cur, abs_base + bs_pos, state.in_ipv6_host, horizon)
                        .map(|abs_at| abs_at - abs_base);
                *auth_at_pos = Some(computed);
                computed.is_some_and(|at| at > bs_pos)
            }
        };
    if has_auth_at {
        return true;
    }
    if first_after == b'\n' && !state.in_non_root_path {
        return false;
    }
    let after_bs_pos = rest.len() - after_bs.len();
    let mut ws_end = after_bs_pos;
    if state.in_non_root_path {
        while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r' | b'\n') {
            ws_end += 1;
        }
    } else {
        while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r') {
            ws_end += 1;
        }
    }
    if ws_end >= bytes.len() {
        return false;
    }
    let has_nl = bytes[after_bs_pos..ws_end].contains(&b'\n');
    let next_ch = rest[ws_end..].chars().next().unwrap();
    if !(state.in_ipv6_host && next_ch == ']') && is_hard_uri_stop(rest, ws_end, next_ch) {
        return false;
    }
    let tok_end = next_uri_token_end(rest, ws_end, state.in_ipv6_host);
    let next_tok = &rest[ws_end..tok_end];
    let scheme_check_tok = if state.in_ipv6_host && next_ch != ']' {
        next_tok.split(']').next().unwrap_or(next_tok)
    } else {
        next_tok
    };
    !next_tok.is_empty()
        && !is_scheme_token(scheme_check_tok)
        && next_tok != "#"
        && ((state.in_non_root_path && !has_nl) || !token_is_log_kv_field(next_tok))
}

fn find_inline_uri_end(
    cur: &str,
    start: usize,
    scheme_len: usize,
    is_opaque_proxy: bool,
    is_special_scheme: bool,
    horizon: &mut AuthorityAtHorizon,
) -> usize {
    let abs_base = start + scheme_len;
    let rest = &cur[abs_base..];
    let bytes = rest.as_bytes();
    let mut start_rel = 0usize;
    let mut auth_at_pos: Option<Option<usize>> = None;

    // WHATWG URL parsing strips ASCII \t/\r/\n and collapses extra leading `/` after `://`.
    // Advance once in O(k) past leading `/\t\r\n` prefixes that bridge into a credentialed
    // authority, opaque proxy share payload, leading-slash authority, bare IP host literal,
    // backslash-path continuation, or host+path/query/fragment URL while never swallowing
    // unrelated multi-line/TSV text after a bare `https://`.
    let prefix_end = bytes
        .iter()
        .take_while(|&&b| matches!(b, b'/' | b'\t' | b'\r' | b'\n'))
        .count();
    if prefix_end > 0 {
        let prefix = &rest[..prefix_end];
        let after_prefix = &rest[prefix_end..];
        let has_ws = prefix.bytes().any(|b| matches!(b, b'\t' | b'\r' | b'\n'));
        if !has_ws {
            start_rel = prefix_end;
        } else if let Some(first_ch) = after_prefix.chars().next()
            && !first_ch.is_whitespace()
            && !matches!(
                first_ch,
                '"' | '\'' | '`' | ')' | ']' | '}' | '>' | ',' | ';'
            )
            && !(first_ch == '\\' && is_hard_escaped_stop_excluding_whatwg_ws(after_prefix, 0))
        {
            let slash_after_ws = prefix
                .bytes()
                .skip_while(|&b| !matches!(b, b'\t' | b'\r' | b'\n'))
                .any(|b| b == b'/');
            let tok_end = next_uri_token_end(rest, prefix_end, first_ch == '[');
            let next_tok = &rest[prefix_end..tok_end];
            let lead_scheme_tok = if first_ch == '[' {
                next_tok.split(']').next().unwrap_or(next_tok)
            } else {
                next_tok
            };
            if !next_tok.is_empty() && !is_scheme_token(lead_scheme_tok) {
                let is_ip_host_literal =
                    is_leading_whatwg_ip_token(rest, prefix_end, next_tok, tok_end);
                let is_leading_bs_ws = first_ch == '\\'
                    && (!is_escaped_stop_boundary(rest, prefix_end, &[])
                        || can_bridge_whatwg_bs_ws(
                            cur,
                            abs_base,
                            prefix_end,
                            BsBridgeState {
                                in_authority: true,
                                in_ipv6_host: false,
                                in_non_root_path: false,
                            },
                            &mut auth_at_pos,
                            horizon,
                        ));
                let has_nl_in_prefix = prefix.bytes().any(|b| b == b'\n');
                let second_tok_bridges = if !has_nl_in_prefix
                    && !token_is_log_kv_field(next_tok)
                    && bytes
                        .get(tok_end)
                        .is_some_and(|&b| matches!(b, b'\t' | b'\r'))
                {
                    let mut ws2_end = tok_end;
                    while ws2_end < bytes.len() && matches!(bytes[ws2_end], b'\t' | b'\r') {
                        ws2_end += 1;
                    }
                    if ws2_end < bytes.len() {
                        let next_ch2 = rest[ws2_end..].chars().next().unwrap();
                        let open_v6 = next_tok.starts_with('[') && !next_tok.contains(']');
                        if (open_v6 && next_ch2 == ']')
                            || !is_hard_uri_stop(rest, ws2_end, next_ch2)
                        {
                            let tok2_end = next_uri_token_end(rest, ws2_end, open_v6);
                            let next_tok2 = &rest[ws2_end..tok2_end];
                            let scheme_check_tok2 = if open_v6 && next_ch2 != ']' {
                                next_tok2.split(']').next().unwrap_or(next_tok2)
                            } else {
                                next_tok2
                            };
                            let bs2_bridges = is_special_scheme
                                && next_ch2 == '\\'
                                && (!is_escaped_stop_boundary(rest, ws2_end, &[])
                                    || can_bridge_whatwg_bs_ws(
                                        cur,
                                        abs_base,
                                        ws2_end,
                                        BsBridgeState {
                                            in_authority: true,
                                            in_ipv6_host: open_v6,
                                            in_non_root_path: false,
                                        },
                                        &mut auth_at_pos,
                                        horizon,
                                    ));
                            !next_tok2.is_empty()
                                && !is_scheme_token(scheme_check_tok2)
                                && !token_is_log_kv_field(next_tok2)
                                && ((next_ch2 == '/'
                                    && bytes
                                        .get(ws2_end + 1)
                                        .is_some_and(|&b| !b.is_ascii_whitespace()))
                                    || next_ch2 == '?'
                                    || (next_ch2 == '#'
                                        && bytes
                                            .get(ws2_end + 1)
                                            .is_some_and(|&b| !b.is_ascii_whitespace()))
                                    || next_ch2 == '@'
                                    || (next_ch2 == ':'
                                        && bytes
                                            .get(ws2_end + 1)
                                            .is_some_and(|&b| !b.is_ascii_whitespace()))
                                    || (next_tok.ends_with(':') && next_ch2.is_ascii_digit())
                                    || (next_tok.ends_with('.')
                                        && next_ch2.is_ascii_alphanumeric())
                                    || (is_special_scheme && has_non_trailing_backslash(next_tok2))
                                    || bs2_bridges
                                    || (next_tok2 != "/" && next_tok2.contains('/'))
                                    || next_tok2.contains('?')
                                    || (next_tok2.len() > 1 && next_tok2.contains('#'))
                                    || (open_v6 && (next_ch2 == ']' || next_tok2.contains(']'))))
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };
                if is_opaque_proxy
                    || slash_after_ws
                    || is_ip_host_literal
                    || is_leading_bs_ws
                    || second_tok_bridges
                    || next_tok.contains('@')
                    || (next_tok != "/" && next_tok.contains('/'))
                    || (is_special_scheme && has_non_trailing_backslash(next_tok))
                    || next_tok.contains('?')
                    || (next_tok.len() > 1 && next_tok.contains('#'))
                {
                    start_rel = prefix_end;
                } else {
                    let last_at = match auth_at_pos {
                        Some(cached) => cached,
                        None => {
                            let computed =
                                find_last_authority_at(cur, abs_base + prefix_end, false, horizon)
                                    .map(|abs_at| abs_at - abs_base);
                            auth_at_pos = Some(computed);
                            computed
                        }
                    };
                    if last_at.is_some_and(|at| at >= prefix_end) {
                        start_rel = prefix_end;
                    }
                }
            }
        }
    }

    let mut in_authority = true;
    let mut in_ipv6_host = false;
    let mut path_start: Option<usize> = None;
    let mut in_query = false;
    let mut pos = start_rel;
    while pos < bytes.len() {
        let c = rest[pos..].chars().next().unwrap();
        if matches!(c, '\t' | '\r' | '\n') {
            let mut ws_end = pos;
            while ws_end < bytes.len() && matches!(bytes[ws_end], b'\t' | b'\r' | b'\n') {
                ws_end += 1;
            }
            if ws_end >= bytes.len() {
                return abs_base + pos;
            }
            let after_ws = &rest[ws_end..];
            let Some(next_ch) = after_ws.chars().next() else {
                return abs_base + pos;
            };
            if !(in_ipv6_host && next_ch == ']') && is_hard_uri_stop(rest, ws_end, next_ch) {
                return abs_base + pos;
            }
            let tok_end = next_uri_token_end(rest, ws_end, in_ipv6_host);
            let next_tok = &rest[ws_end..tok_end];
            // Match `find_last_authority_at`'s exact stop rule (checking only the pre-`]` slice
            // when inside `[...]`) so `AuthorityAtHorizon` stays 100% consistent and O(N).
            let scheme_check_tok = if in_ipv6_host && next_ch != ']' {
                next_tok.split(']').next().unwrap_or(next_tok)
            } else {
                next_tok
            };
            if next_tok.is_empty() || is_scheme_token(scheme_check_tok) {
                return abs_base + pos;
            }
            let prev_byte = if pos > start_rel {
                Some(bytes[pos - 1])
            } else {
                None
            };
            let has_nl = bytes[pos..ws_end].contains(&b'\n');
            let in_non_root_path_after_bs =
                !in_authority && path_start.is_some_and(|ps| pos > ps + 2);
            let prev_is_bs_ws = prev_byte == Some(b'\\')
                && (!has_nl || in_non_root_path_after_bs)
                && next_tok != "#"
                && ((in_non_root_path_after_bs && !has_nl) || !token_is_log_kv_field(next_tok));
            let can_bridge_bs_at_ws = next_ch == '\\'
                && (!is_escaped_stop_boundary(rest, ws_end, &[])
                    || can_bridge_whatwg_bs_ws(
                        cur,
                        abs_base,
                        ws_end,
                        BsBridgeState {
                            in_authority,
                            in_ipv6_host,
                            in_non_root_path: !in_authority
                                && path_start.is_some_and(|ps| ws_end > ps + 1),
                        },
                        &mut auth_at_pos,
                        horizon,
                    ));
            let should_bridge = if in_authority {
                let has_at_ahead = match auth_at_pos {
                    Some(cached) => cached.is_some_and(|at| at >= ws_end),
                    None => {
                        let computed =
                            find_last_authority_at(cur, abs_base + pos, in_ipv6_host, horizon)
                                .map(|abs_at| abs_at - abs_base);
                        auth_at_pos = Some(computed);
                        computed.is_some_and(|at| at >= ws_end)
                    }
                };
                let next_is_dot_host_cont = next_ch == '.'
                    && after_ws
                        .as_bytes()
                        .get(1)
                        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'-');
                let prev_is_dot_host_cont = prev_byte == Some(b'.')
                    && !has_nl
                    && !token_is_log_kv_field(next_tok)
                    && next_ch.is_ascii_alphanumeric();
                let next_continues_authority_tail = !token_is_log_kv_field(next_tok)
                    && ((next_tok != "/" && next_tok.contains('/'))
                        || (is_special_scheme && has_non_trailing_backslash(next_tok))
                        || next_tok.contains('?')
                        || (next_tok.len() > 1 && next_tok.contains('#'))
                        || next_is_dot_host_cont
                        || prev_is_dot_host_cont);
                let ipv6_part = next_tok.split(']').next().unwrap_or(next_tok);
                let looks_ipv6_chunk = is_ipv6_chunk_chars(ipv6_part);
                let nl_hex_before_v6_delim =
                    has_nl && looks_ipv6_chunk && !next_tok.contains(']') && {
                        let mut ws2 = tok_end;
                        while ws2 < bytes.len() && matches!(bytes[ws2], b'\t' | b'\r' | b'\n') {
                            ws2 += 1;
                        }
                        ws2 > tok_end
                            && (bytes.get(ws2).is_some_and(|&b| b == b':' || b == b']')
                                || peek_ipv6_colon_continuation(rest, tok_end))
                    };
                let bridges_ipv6_ws = in_ipv6_host
                    && !token_is_log_kv_field(next_tok)
                    && (next_ch == ']'
                        || next_tok.contains(']')
                        || (looks_ipv6_chunk && (ipv6_part.contains(':') || !has_nl))
                        || nl_hex_before_v6_delim);
                has_at_ahead
                    || prev_is_bs_ws
                    || bridges_ipv6_ws
                    || next_ch == '@'
                    || (next_ch == ':'
                        && after_ws
                            .as_bytes()
                            .get(1)
                            .is_some_and(|&b| !b.is_ascii_whitespace()))
                    || can_bridge_bs_at_ws
                    || (next_ch == '/'
                        && after_ws
                            .as_bytes()
                            .get(1)
                            .is_some_and(|&b| !b.is_ascii_whitespace()))
                    || (prev_byte == Some(b':') && next_ch.is_ascii_digit())
                    || next_continues_authority_tail
            } else {
                let prev_is_query_eq = prev_byte == Some(b'=');
                let prev_is_query_sep = matches!(prev_byte, Some(b'?' | b'&'));
                let first_amp_seg = next_tok.split('&').next().unwrap_or(next_tok);
                let val_after_eq_ok =
                    prev_is_query_eq && !first_amp_seg.trim_end_matches('=').contains('=');
                let prev_is_path_slash_ws = prev_byte == Some(b'/')
                    && next_tok != "#"
                    && path_start.is_some_and(|ps| {
                        if pos > ps + 1 {
                            !has_nl || !token_is_log_kv_field(next_tok)
                        } else {
                            pos == ps + 1 && !has_nl && !token_is_log_kv_field(next_tok)
                        }
                    });
                let next_tok_trailing_bs_bridges = is_special_scheme
                    && !has_nl
                    && next_tok.ends_with('\\')
                    && !next_tok.trim_end_matches('\\').is_empty()
                    && bytes
                        .get(tok_end)
                        .is_some_and(|&b| matches!(b, b'\t' | b'\r'))
                    && {
                        let bs_run_start = ws_end + next_tok.trim_end_matches('\\').len();
                        can_bridge_whatwg_bs_ws(
                            cur,
                            abs_base,
                            bs_run_start,
                            BsBridgeState {
                                in_authority: false,
                                in_ipv6_host: false,
                                in_non_root_path: path_start
                                    .is_some_and(|ps| bs_run_start > ps + 1),
                            },
                            &mut auth_at_pos,
                            horizon,
                        )
                    };
                let next_continues_mid_path = !has_nl
                    && !token_is_log_kv_field(next_tok)
                    && ((next_ch != '/' && next_tok.contains('/'))
                        || (is_special_scheme
                            && next_ch != '\\'
                            && has_non_trailing_backslash(next_tok))
                        || next_tok_trailing_bs_bridges
                        || next_tok.contains('?')
                        || (next_tok.len() > 1 && next_tok.contains('#')));
                let query_mid_val_ws =
                    in_query && !has_nl && next_tok != "#" && !first_amp_seg.contains('=');
                let next_continues_path_or_query = matches!(next_ch, '/' | '?' | '&')
                    || (in_query && next_ch == '=')
                    || (next_ch == '#'
                        && after_ws
                            .as_bytes()
                            .get(1)
                            .is_some_and(|&b| !b.is_ascii_whitespace()));
                val_after_eq_ok
                    || prev_is_query_sep
                    || prev_is_path_slash_ws
                    || prev_is_bs_ws
                    || (!has_nl && !token_is_log_kv_field(next_tok) && can_bridge_bs_at_ws)
                    || next_continues_mid_path
                    || query_mid_val_ws
                    || next_continues_path_or_query
            };
            if should_bridge {
                pos = ws_end;
                continue;
            }
            return abs_base + pos;
        }

        if in_authority {
            if c == '[' {
                in_ipv6_host = true;
                pos += 1;
                continue;
            }
            if c == ']' && in_ipv6_host {
                in_ipv6_host = false;
                pos += 1;
                continue;
            }
            if matches!(c, '?' | '#') || (c == '/' && !(pos > 0 && bytes[pos - 1] == b'\\')) {
                in_authority = false;
                if c == '/' && path_start.is_none() {
                    path_start = Some(pos);
                }
            } else if is_special_scheme && !in_ipv6_host && c == '\\' {
                let has_at_ahead = match auth_at_pos {
                    Some(cached) => cached.is_some_and(|at| at > pos),
                    None => {
                        let computed = find_last_authority_at(cur, abs_base + pos, false, horizon)
                            .map(|abs_at| abs_at - abs_base);
                        auth_at_pos = Some(computed);
                        computed.is_some_and(|at| at > pos)
                    }
                };
                if !has_at_ahead && !is_hard_escaped_stop_excluding_whatwg_ws(rest, pos) {
                    in_authority = false;
                    if path_start.is_none() {
                        path_start = Some(pos);
                    }
                }
            }
        }
        if c == '?' {
            in_query = true;
        }
        if c == '\\' && is_escaped_stop_boundary(rest, pos, &[]) {
            if !can_bridge_whatwg_bs_ws(
                cur,
                abs_base,
                pos,
                BsBridgeState {
                    in_authority,
                    in_ipv6_host,
                    in_non_root_path: !in_authority && path_start.is_some_and(|ps| pos > ps + 1),
                },
                &mut auth_at_pos,
                horizon,
            ) {
                return abs_base + pos;
            }
        } else if c.is_whitespace()
            || matches!(c, '"' | '\'' | '`' | ')' | ']' | '}' | '>' | ',' | ';')
        {
            return abs_base + pos;
        }
        pos += c.len_utf8();
    }
    cur.len()
}

pub(crate) fn find_non_nil_uuid_edits(input: &str) -> Vec<(usize, usize, String)> {
    let bytes = input.as_bytes();
    if bytes.len() < 36 {
        return Vec::new();
    }
    let mut edits = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 36 <= bytes.len()
            && input.is_char_boundary(i)
            && input.is_char_boundary(i + 36)
            && (i == 0 || !bytes[i - 1].is_ascii_hexdigit())
            && (i + 36 == bytes.len() || !bytes[i + 36].is_ascii_hexdigit())
        {
            let slice = &input[i..i + 36];
            let s_bytes = slice.as_bytes();
            let looks_uuid = s_bytes[8] == b'-'
                && s_bytes[13] == b'-'
                && s_bytes[18] == b'-'
                && s_bytes[23] == b'-'
                && s_bytes
                    .iter()
                    .enumerate()
                    .all(|(idx, b)| matches!(idx, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit());
            if looks_uuid && slice != "00000000-0000-0000-0000-000000000000" {
                edits.push((i, i + 36, REDACTED_SECRET.to_string()));
                i += 36;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        i += ch.len_utf8();
    }
    edits
}

/// Returns `true` when a raw URL contains `'\\'` in its pre-path authority before `'@'`.
/// WHATWG `Url::parse` removes ASCII `\t`/`\r`/`\n` and normalizes `'\\'` to `'/'` in special
/// schemes (`http://`, `https://`, `ws://`, `wss://`), which would otherwise promote raw
/// credentials preceding `'\\'` into `parsed.host_str()`.
pub(crate) fn has_backslash_before_at_in_authority(trimmed: &str) -> bool {
    let normalized: Cow<'_, str> = if trimmed.bytes().any(|b| matches!(b, b'\t' | b'\r' | b'\n')) {
        Cow::Owned(
            trimmed
                .chars()
                .filter(|&c| !matches!(c, '\t' | '\r' | '\n'))
                .collect(),
        )
    } else {
        Cow::Borrowed(trimmed)
    };
    let after_scheme_opt = normalized
        .split_once("://")
        .or_else(|| normalized.split_once(":/\\"))
        .or_else(|| normalized.split_once(":\\\\"))
        .or_else(|| normalized.split_once(":\\/"))
        .map(|(_, after)| after);
    if let Some(after_scheme) = after_scheme_opt {
        let after_slashes = after_scheme.trim_start_matches(['/', '\\']);
        let pre_query = after_slashes
            .split(['?', '#'])
            .next()
            .unwrap_or(after_slashes);
        let raw_before_slash = pre_query.split('/').next().unwrap_or(pre_query);
        if let (Some(bs), Some(at)) = (raw_before_slash.find('\\'), pre_query.rfind('@'))
            && bs < at
        {
            return true;
        }
    }
    false
}

/// Restore canonical uppercase `***REDACTED***` / `***REDACTED_URL***` tokens after
/// `url::Url::parse` lowercases domain labels (so URLs like `https://<uuid>.example/path` remain
/// strictly idempotent and never corrupt uppercase placeholders into `***redacted***`).
pub(crate) fn restore_placeholder_case(host: &str) -> String {
    if !host.contains('*') {
        return host.to_string();
    }
    let lower = host.to_ascii_lowercase();
    let mut out = String::with_capacity(host.len());
    let mut i = 0usize;
    while i < host.len() {
        if lower[i..].starts_with("***redacted_url***") {
            out.push_str("***REDACTED_URL***");
            i += "***redacted_url***".len();
        } else if lower[i..].starts_with("***redacted***") {
            out.push_str(REDACTED_SECRET);
            i += "***redacted***".len();
        } else {
            let ch = host[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn raw_path_has_dot_segment(raw_path: &str) -> bool {
    raw_path == "/."
        || raw_path == "\\."
        || raw_path.ends_with("/.")
        || raw_path.ends_with("\\.")
        || raw_path.contains("/./")
        || raw_path.contains("/.\\")
        || raw_path.contains("\\./")
        || raw_path.contains("\\.\\")
        || raw_path.contains("..")
        || raw_path
            .as_bytes()
            .windows(3)
            .any(|w| w[0] == b'%' && w[1] == b'2' && w[2].eq_ignore_ascii_case(&b'e'))
}

fn redact_url_inline(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(scheme) = trimmed.strip_suffix("://***REDACTED***")
        && matches!(
            scheme.to_ascii_lowercase().as_str(),
            "http" | "https" | "ws" | "wss" | "tls" | "quic" | "h3" | "doq"
        )
    {
        return raw.to_string();
    }
    if trimmed.bytes().any(|b| matches!(b, b'\t' | b'\r' | b'\n'))
        || has_backslash_before_at_in_authority(trimmed)
    {
        return "***REDACTED_URL***".to_string();
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return "***REDACTED_URL***".to_string();
    };
    let scheme = parsed.scheme();
    if matches!(scheme, "tls" | "quic" | "h3" | "doq") {
        let Some(raw_host) = parsed.host_str().filter(|h| !h.is_empty()) else {
            return "***REDACTED_URL***".to_string();
        };
        if raw_host.contains('\\')
            || raw_host.contains('%')
            || raw_host.contains('@')
            || raw_host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return "***REDACTED_URL***".to_string();
        }
        let raw_after_scheme = trimmed.split_once("://").map(|(_, a)| a).unwrap_or("");
        if raw_after_scheme.starts_with('/') || raw_after_scheme.contains('\\') {
            return "***REDACTED_URL***".to_string();
        }
        let raw_path = raw_after_scheme
            .find('/')
            .map(|idx| &raw_after_scheme[idx..])
            .unwrap_or("");
        let has_dot_segment = raw_path_has_dot_segment(raw_path);
        let has_sensitive_tail = !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || has_dot_segment
            || (parsed.path() != "/" && !parsed.path().is_empty());
        return if has_sensitive_tail {
            let host = restore_placeholder_case(raw_host);
            let port_suffix = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{scheme}://{host}{port_suffix}/{REDACTED_SECRET}")
        } else {
            // Verbatim No-Op Invariant: benign URLs with no sensitive components return untouched.
            raw.to_string()
        };
    }

    let is_non_loopback_ip = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => !v4.is_loopback(),
        Some(url::Host::Ipv6(v6)) => {
            !(v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()))
        }
        _ => false,
    };
    if is_non_loopback_ip {
        return format!("{scheme}://{REDACTED_SECRET}");
    }
    let Some(raw_host) = parsed.host_str().filter(|h| !h.is_empty()) else {
        return "***REDACTED_URL***".to_string();
    };
    let raw_after_scheme = trimmed.split_once("://").map(|(_, a)| a).unwrap_or("");
    let raw_after_slashes = raw_after_scheme.trim_start_matches(['/', '\\']);
    let raw_path = raw_after_slashes
        .find(['/', '\\'])
        .map(|idx| &raw_after_slashes[idx..])
        .unwrap_or("");
    let has_dot_segment = raw_path_has_dot_segment(raw_path);
    let has_whatwg_backslash = raw_after_scheme.contains('\\');
    let has_sensitive_tail = !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || has_dot_segment
        || has_whatwg_backslash
        || (parsed.path() != "/" && !parsed.path().is_empty());
    if has_sensitive_tail {
        let host = restore_placeholder_case(raw_host);
        let port_suffix = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
        format!("{scheme}://{host}{port_suffix}/{REDACTED_SECRET}")
    } else {
        // Verbatim No-Op Invariant: benign URLs with no sensitive components return untouched.
        raw.to_string()
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
            flow,
            reality_opts,
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
            let reality_sig = reality_opts
                .as_ref()
                .map(|r| {
                    format!(
                        "reality:{}:{}",
                        r.public_key.trim(),
                        r.short_id
                            .as_deref()
                            .unwrap_or("")
                            .trim()
                            .to_ascii_lowercase()
                    )
                })
                .unwrap_or_default();
            format!(
                "vless|{}|{}|{}|{}|{}|{}|{}|{}|{}",
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
                ws_sig,
                flow.as_deref().unwrap_or("").trim().to_ascii_lowercase(),
                reality_sig
            )
        }
        ProxyNodeConfig::Vmess {
            server,
            port,
            uuid,
            cipher,
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
                "vmess|{}|{}|{}|{}|{}|{}|{}",
                server.trim().to_ascii_lowercase(),
                port,
                uuid,
                cipher.trim().to_ascii_lowercase(),
                tls,
                servername
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase(),
                ws_sig
            )
        }
        ProxyNodeConfig::Hysteria2 {
            server,
            port,
            ports,
            password,
            obfs,
            obfs_password,
            sni,
            ..
        } => format!(
            "hysteria2|{}|{}|{}|{}|{}|{}|{}",
            server.trim().to_ascii_lowercase(),
            port,
            ports.as_deref().unwrap_or("").trim(),
            password.trim(),
            obfs.as_deref().unwrap_or("").trim().to_ascii_lowercase(),
            obfs_password.as_deref().unwrap_or("").trim(),
            sni.as_deref().unwrap_or("").trim().to_ascii_lowercase()
        ),
        ProxyNodeConfig::Tuic {
            server,
            port,
            uuid,
            password,
            udp_relay_mode,
            sni,
            ..
        } => format!(
            "tuic|{}|{}|{}|{}|{}|{}",
            server.trim().to_ascii_lowercase(),
            port,
            uuid,
            password.trim(),
            udp_relay_mode
                .as_deref()
                .unwrap_or("native")
                .trim()
                .to_ascii_lowercase(),
            sni.as_deref().unwrap_or("").trim().to_ascii_lowercase()
        ),
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

/// Parse standard proxy share URIs (`ss://`, `vmess://`, `vless://`, `trojan://`, `hysteria2://`,
/// `hy2://`, `tuic://`, `anytls://`, `socks5://`, `http-proxy://`) into a validated `ProxyNodeConfig`.
pub fn parse_proxy_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let trimmed = trim_bom_and_controls(raw);
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
    } else if lower_prefix.starts_with("vmess://") {
        parse_vmess_uri(&trimmed[8..])
    } else if lower_prefix.starts_with("hysteria2://") {
        let normalized = format!("hysteria2://{}", &trimmed[12..]);
        parse_hysteria2_uri(&normalized)
    } else if lower_prefix.starts_with("hy2://") {
        let normalized = format!("hysteria2://{}", &trimmed[6..]);
        parse_hysteria2_uri(&normalized)
    } else if lower_prefix.starts_with("tuic://") {
        let normalized = format!("tuic://{}", &trimmed[7..]);
        parse_tuic_uri(&normalized)
    } else if lower_prefix.starts_with("anytls://") {
        let normalized = format!("anytls://{}", &trimmed[9..]);
        parse_anytls_uri(&normalized)
    } else if lower_prefix.starts_with("trojan://") {
        let normalized = format!("trojan://{}", &trimmed[9..]);
        parse_trojan_uri(&normalized)
    } else if lower_prefix.starts_with("socks5s://") {
        parse_socks5_uri(&trimmed[10..], true)
    } else if lower_prefix.starts_with("socks5h://") {
        parse_socks5_uri(&trimmed[10..], false)
    } else if lower_prefix.starts_with("socks5://") {
        parse_socks5_uri(&trimmed[9..], false)
    } else if lower_prefix.starts_with("socks://") {
        parse_socks5_uri(&trimmed[8..], false)
    } else if lower_prefix.starts_with("https-proxy://") {
        parse_http_proxy_uri(&trimmed[14..], true)
    } else if lower_prefix.starts_with("http-proxy://") {
        parse_http_proxy_uri(&trimmed[13..], false)
    } else if lower_prefix.starts_with("https://")
        && has_proxy_authority_without_subpath(&trimmed[8..])
    {
        parse_http_proxy_uri(&trimmed[8..], true)
    } else if lower_prefix.starts_with("http://")
        && has_proxy_authority_without_subpath(&trimmed[7..])
    {
        parse_http_proxy_uri(&trimmed[7..], false)
    } else if let Some((scheme, _)) = trimmed.split_once("://") {
        let safe_scheme: String = scheme
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            .take(16)
            .collect();
        if safe_scheme.is_empty() {
            Err(ProxyError::Config(
                "unsupported proxy URI scheme (expected ss://, vmess://, vless://, trojan://, hysteria2://, hy2://, tuic://, anytls://, socks5://, or http-proxy://)".into(),
            ))
        } else {
            Err(ProxyError::Config(format!(
                "unsupported proxy URI scheme '{safe_scheme}://' (expected ss://, vmess://, vless://, trojan://, hysteria2://, hy2://, tuic://, anytls://, socks5://, or http-proxy://)"
            )))
        }
    } else {
        Err(ProxyError::Config(
            "invalid proxy share link format (expected ss://, vmess://, vless://, trojan://, hysteria2://, hy2://, tuic://, anytls://, socks5://, or http-proxy://)".into(),
        ))
    }
}

fn has_proxy_authority_without_subpath(without_scheme: &str) -> bool {
    let main_part = without_scheme
        .split_once('#')
        .map(|(m, _)| m)
        .unwrap_or(without_scheme);
    let main_part = main_part
        .split_once('?')
        .map(|(m, _)| m)
        .unwrap_or(main_part);
    let authority = match main_part.split_once('/') {
        Some((auth, "")) => auth,
        Some(_) => return false,
        None => main_part,
    };
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    split_host_port(hostport).is_ok_and(|(h, p)| !h.is_empty() && p > 0)
}

fn has_explicit_userinfo_proxy_authority(without_scheme: &str) -> bool {
    if !has_proxy_authority_without_subpath(without_scheme) {
        return false;
    }
    let main_part = without_scheme
        .split_once('#')
        .map(|(m, _)| m)
        .unwrap_or(without_scheme);
    let (main_part, query) = main_part.split_once('?').unwrap_or((main_part, ""));
    let q_lc = query.to_ascii_lowercase();
    if q_lc.contains("token=") || q_lc.contains("flag=") || q_lc.contains("sub=") {
        return false;
    }
    let authority = main_part.trim_end_matches('/');
    authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| !userinfo.trim().is_empty())
}

pub fn is_proxy_uri_token(token: &str) -> bool {
    let t = trim_bom_and_controls(token);
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
    match lc.as_str() {
        "clash" => false,
        "http" | "https" => has_explicit_userinfo_proxy_authority(rest),
        _ => true,
    }
}

fn contains_uri_scheme_line(text: &str) -> bool {
    text.lines().any(|l| {
        let t = trim_bom_and_controls(l);
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
    let trimmed = trim_bom_and_controls(input);
    if trimmed.is_empty() || contains_uri_scheme_line(trimmed) {
        return None;
    }
    let bytes = decode_b64_flexible(trimmed)?;
    let decoded = String::from_utf8(bytes).ok()?;
    let clean_decoded = trim_bom_and_controls(&decoded);
    if contains_uri_scheme_line(clean_decoded) {
        Some(clean_decoded.to_string())
    } else {
        None
    }
}

fn extract_uri_tokens(input: &str) -> Result<Vec<String>> {
    let trimmed = trim_bom_and_controls(input);
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
        let line = trim_bom_and_controls(line);
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

fn format_uri_host_port(server: &str, port: u16) -> String {
    let clean = server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if clean.contains(':') {
        format!("[{clean}]:{port}")
    } else {
        format!("{clean}:{port}")
    }
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
            let host_port = format_uri_host_port(server, *port);
            format!(
                "ss://{userinfo}@{host_port}#{}",
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
            flow,
            reality_opts,
            client_fingerprint,
            udp,
            ..
        } => {
            let security = if reality_opts.is_some() {
                "reality"
            } else if *tls {
                "tls"
            } else {
                "none"
            };
            let ws = node.effective_ws_opts();
            let net_type = if ws.is_some() { "ws" } else { "tcp" };
            let mut params = vec![
                format!("type={net_type}"),
                format!("encryption={encryption}"),
                format!("security={security}"),
            ];
            if let Some(f) = flow.as_deref().map(str::trim)
                && !f.is_empty()
                && !f.eq_ignore_ascii_case("none")
            {
                params.push(format!("flow={}", percent_encode_component(f)));
            }
            if let Some(fp) = client_fingerprint.as_deref().map(str::trim)
                && !fp.is_empty()
            {
                params.push(format!("fp={}", percent_encode_component(fp)));
            }
            if let Some(ropts) = reality_opts {
                params.push(format!(
                    "pbk={}",
                    percent_encode_component(&ropts.public_key)
                ));
                if let Some(sid) = ropts.short_id.as_deref().filter(|s| !s.is_empty()) {
                    params.push(format!("sid={}", percent_encode_component(sid)));
                }
                if let Some(spx) = ropts.spider_x.as_deref().filter(|s| !s.is_empty()) {
                    params.push(format!("spx={}", percent_encode_component(spx)));
                }
            }
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
            if *skip_cert_verify && reality_opts.is_none() {
                params.push("allowInsecure=1".to_string());
            }
            if !*udp {
                params.push("udp=0".to_string());
            }
            let host_port = format_uri_host_port(server, *port);
            format!(
                "vless://{uuid}@{host_port}?{}#{}",
                params.join("&"),
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Vmess {
            name,
            server,
            port,
            uuid,
            alter_id,
            cipher,
            global_padding,
            tls,
            servername,
            skip_cert_verify,
            alpn,
            udp,
            ..
        } => {
            let ws = node.effective_ws_opts();
            let (net_str, ws_host, ws_path) = if let Some(ws_cfg) = ws {
                let (clean_path, max_ed, _) = ws_cfg.normalized_parts();
                let exported_path = if max_ed > 0 && !ws_cfg.path.contains("ed=") {
                    if clean_path.contains('?') {
                        format!("{clean_path}&ed={max_ed}")
                    } else {
                        format!("{clean_path}?ed={max_ed}")
                    }
                } else {
                    ws_cfg.path.clone()
                };
                (
                    "ws",
                    ws_cfg.host_header().unwrap_or("").to_string(),
                    exported_path,
                )
            } else {
                ("tcp", String::new(), String::new())
            };
            let mut obj = serde_json::Map::new();
            obj.insert("v".into(), serde_json::Value::String("2".into()));
            obj.insert("ps".into(), serde_json::Value::String(name.clone()));
            obj.insert("add".into(), serde_json::Value::String(server.clone()));
            obj.insert("port".into(), serde_json::Value::String(port.to_string()));
            obj.insert("id".into(), serde_json::Value::String(uuid.to_string()));
            obj.insert(
                "aid".into(),
                serde_json::Value::String(alter_id.to_string()),
            );
            obj.insert("scy".into(), serde_json::Value::String(cipher.clone()));
            obj.insert("net".into(), serde_json::Value::String(net_str.into()));
            obj.insert("type".into(), serde_json::Value::String("none".into()));
            obj.insert("host".into(), serde_json::Value::String(ws_host));
            obj.insert("path".into(), serde_json::Value::String(ws_path));
            obj.insert(
                "tls".into(),
                serde_json::Value::String(if *tls { "tls" } else { "" }.into()),
            );
            obj.insert(
                "sni".into(),
                serde_json::Value::String(servername.clone().unwrap_or_default()),
            );
            obj.insert("alpn".into(), serde_json::Value::String(alpn.join(",")));
            if *skip_cert_verify {
                obj.insert("allowInsecure".into(), serde_json::Value::Number(1.into()));
            }
            if *global_padding {
                obj.insert("globalPadding".into(), serde_json::Value::Bool(true));
            }
            if !*udp {
                obj.insert("udp".into(), serde_json::Value::Bool(false));
            }
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(serde_json::Value::Object(obj).to_string());
            format!("vmess://{encoded}")
        }
        ProxyNodeConfig::Hysteria2 {
            name,
            server,
            port,
            ports,
            password,
            obfs,
            obfs_password,
            up,
            down,
            sni,
            skip_cert_verify,
            alpn,
            udp,
        } => {
            let mut params = Vec::new();
            if let Some(s) = sni.as_deref().filter(|s| !s.is_empty()) {
                params.push(format!("sni={}", percent_encode_component(s)));
            }
            if let Some(ps) = ports.as_deref().filter(|s| !s.trim().is_empty()) {
                params.push(format!("mport={}", percent_encode_component(ps.trim())));
            }
            if let Some(om) = obfs
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
            {
                params.push(format!("obfs={}", percent_encode_component(om)));
                if let Some(op) = obfs_password.as_deref().filter(|s| !s.is_empty()) {
                    params.push(format!("obfs-password={}", percent_encode_component(op)));
                }
            }
            if let Some(u) = up.as_deref().filter(|s| !s.trim().is_empty()) {
                params.push(format!("up={}", percent_encode_component(u.trim())));
            }
            if let Some(d) = down.as_deref().filter(|s| !s.trim().is_empty()) {
                params.push(format!("down={}", percent_encode_component(d.trim())));
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
            if !*udp {
                params.push("udp=0".to_string());
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            let host_port = format_uri_host_port(server, *port);
            format!(
                "hysteria2://{}@{host_port}{query}#{}",
                percent_encode_component(password),
                percent_encode_fragment(name)
            )
        }
        ProxyNodeConfig::Tuic {
            name,
            server,
            port,
            uuid,
            password,
            udp_relay_mode,
            congestion_controller,
            reduce_rtt,
            disable_sni,
            heartbeat_interval,
            sni,
            skip_cert_verify,
            alpn,
            udp,
        } => {
            let mut params = Vec::new();
            if let Some(s) = sni.as_deref().filter(|s| !s.is_empty()) {
                params.push(format!("sni={}", percent_encode_component(s)));
            }
            if let Some(cc) = congestion_controller
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                params.push(format!(
                    "congestion_control={}",
                    percent_encode_component(cc)
                ));
            }
            if let Some(urm) = udp_relay_mode
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                params.push(format!("udp_relay_mode={}", percent_encode_component(urm)));
            }
            if !alpn.is_empty() {
                params.push(format!(
                    "alpn={}",
                    percent_encode_component(&alpn.join(","))
                ));
            }
            if *reduce_rtt {
                params.push("reduce_rtt=1".to_string());
            }
            if *disable_sni {
                params.push("disable_sni=1".to_string());
            }
            if *heartbeat_interval != 10_000 {
                params.push(format!("heartbeat={heartbeat_interval}"));
            }
            if *skip_cert_verify {
                params.push("allow_insecure=1".to_string());
            }
            if !*udp {
                params.push("udp=0".to_string());
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            let host_port = format_uri_host_port(server, *port);
            format!(
                "tuic://{uuid}:{}@{host_port}{query}#{}",
                percent_encode_component(password),
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
            udp,
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
            if !*udp {
                params.push("udp=0".to_string());
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            let host_port = format_uri_host_port(server, *port);
            format!(
                "anytls://{}@{host_port}{query}#{}",
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
                let (clean_path, max_ed, hdr_name) = ws_cfg.normalized_parts();
                params.push("type=ws".to_string());
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
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            let host_port = format_uri_host_port(server, *port);
            format!(
                "trojan://{}@{host_port}{query}#{}",
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
            let host_port = format_uri_host_port(server, *port);
            format!(
                "{scheme}://{auth}{host_port}{query}#{}",
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
            let host_port = format_uri_host_port(server, *port);
            format!(
                "{scheme}://{auth}{host_port}{query}#{}",
                percent_encode_fragment(name)
            )
        }
    }
}

pub(crate) fn decode_b64_flexible(s: &str) -> Option<Vec<u8>> {
    let compact: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{feff}' && *c != '\0')
        .collect();
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

fn apply_ss_query_params(query: &str, udp: &mut bool) -> Result<()> {
    if query.is_empty() {
        return Ok(());
    }
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
                    *udp = false;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_ss_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let without_scheme = raw.strip_prefix("ss://").unwrap_or(raw);
    let (main_part, mut fragment) = match without_scheme.split_once('#') {
        Some((m, f)) => (m, Some(percent_decode_str(f))),
        None => (without_scheme, None),
    };
    let (main_part, query) = main_part.split_once('?').unwrap_or((main_part, ""));
    let main_part = main_part.trim_end_matches('/');

    let mut udp = true;
    apply_ss_query_params(query, &mut udp)?;

    let (cipher, password, server, port) = if let Some((userinfo, hostport)) =
        main_part.rsplit_once('@')
    {
        let decoded_user = if userinfo.contains(':') {
            percent_decode_str(userinfo)
        } else {
            let unescaped = percent_decode_str(userinfo);
            let bytes = decode_b64_flexible(&unescaped)
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
        let unescaped_main = percent_decode_str(main_part);
        let bytes = decode_b64_flexible(&unescaped_main)
            .ok_or_else(|| ProxyError::Config("invalid legacy Base64 ss:// URI".into()))?;
        let full = String::from_utf8(bytes)
            .map_err(|_| ProxyError::Config("invalid UTF-8 in legacy ss:// URI".into()))?;
        let (inner_main, inner_frag) = match full.split_once('#') {
            Some((m, f)) => (m, Some(percent_decode_str(f))),
            None => (full.as_str(), None),
        };
        if fragment.is_none() {
            fragment = inner_frag;
        }
        let (inner_main, inner_query) = inner_main.split_once('?').unwrap_or((inner_main, ""));
        apply_ss_query_params(inner_query, &mut udp)?;
        let inner_main = inner_main.trim_end_matches('/');
        let (userinfo, hostport) = inner_main
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

/// Decode RFC 3986 URI query parameters without `application/x-www-form-urlencoded` `+` -> `' '`
/// translation so literal `+` in WebSocket paths (`?path=/ws+v2`) or Base64/PQ tokens is preserved.
fn raw_query_pairs(parsed: &Url) -> Vec<(String, String)> {
    let Some(q) = parsed.query() else {
        return Vec::new();
    };
    q.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode_str(k), percent_decode_str(v))
        })
        .collect()
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
    let mut security_mode = "none".to_string();
    let mut servername = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut flow: Option<String> = None;
    let mut reality_pbk: Option<String> = None;
    let mut reality_sid: Option<String> = None;
    let mut reality_spx: Option<String> = None;
    let mut client_fingerprint: Option<String> = None;
    let mut net_type = "tcp".to_string();
    let mut ws_path: Option<String> = None;
    let mut ws_host: Option<String> = None;
    let mut ws_max_ed: Option<usize> = None;
    let mut ws_ed_hdr: Option<String> = None;
    let mut udp = true;
    let mut remark_fallback = None;

    for (k, v) in raw_query_pairs(&parsed) {
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
                    "" | "none" => {
                        tls = false;
                        security_mode = "none".to_string();
                    }
                    "tls" => {
                        tls = true;
                        security_mode = "tls".to_string();
                    }
                    "reality" => {
                        tls = true;
                        security_mode = "reality".to_string();
                    }
                    _ => {
                        return Err(ProxyError::Config(format!(
                            "VLESS security '{}' is not supported (supported: none, tls, reality)",
                            safe_token_preview(val_trimmed)
                        )));
                    }
                }
            }
            "tls" => {
                if matches!(
                    val_trimmed.to_ascii_lowercase().as_str(),
                    "1" | "true" | "tls"
                ) {
                    tls = true;
                    if security_mode == "none" {
                        security_mode = "tls".to_string();
                    }
                } else if matches!(val_trimmed.to_ascii_lowercase().as_str(), "0" | "false") {
                    tls = false;
                    if security_mode == "tls" {
                        security_mode = "none".to_string();
                    }
                }
            }
            "flow" => {
                let vf = VlessVisionFlow::parse(val_trimmed).map_err(|_| {
                    ProxyError::Config(format!(
                        "VLESS flow '{}' is not supported (supported: xtls-rprx-vision, xtls-rprx-vision-udp443)",
                        safe_token_preview(val_trimmed)
                    ))
                })?;
                flow = vf.map(|f| f.as_str().to_string());
            }
            "pbk" | "publickey" | "public-key" | "public_key" => {
                if !val_trimmed.is_empty() {
                    reality_pbk = Some(val_trimmed.to_string());
                }
            }
            "sid" | "shortid" | "short-id" | "short_id" => {
                if !val_trimmed.is_empty() {
                    reality_sid = Some(val_trimmed.to_string());
                }
            }
            "spx" | "spiderx" | "spider-x" | "spider_x" => {
                if !val_trimmed.is_empty() {
                    reality_spx = Some(val_trimmed.to_string());
                }
            }
            "fp" | "client-fingerprint" | "client_fingerprint" => {
                if !val_trimmed.is_empty() {
                    client_fingerprint = Some(val_trimmed.to_string());
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
            "servicename" | "seed" | "quicsecurity" | "extra" => {
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
            "allowinsecure" | "insecure" | "skip-cert-verify" => {
                match val_trimmed.to_ascii_lowercase().as_str() {
                    "1" | "true" => skip_cert_verify = true,
                    "0" | "false" | "" => skip_cert_verify = false,
                    other => {
                        return Err(ProxyError::Config(format!(
                            "invalid VLESS allowInsecure value '{}' (expected 0, 1, true, or false)",
                            safe_token_preview(other)
                        )));
                    }
                }
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
            "remark" | "remarks" if !val_trimmed.is_empty() => {
                remark_fallback = Some(val_trimmed.to_string());
            }
            _ => {
                // Ignore benign vendor/panel client hints (e.g. tfo, mux, v)
            }
        }
    }

    let reality_opts = if security_mode == "reality" {
        if net_type != "tcp" {
            return Err(ProxyError::Config(
                "VLESS REALITY requires TCP transport (WebSocket is incompatible)".into(),
            ));
        }
        if encryption != "none" {
            return Err(ProxyError::Config(
                "VLESS REALITY cannot be combined with VLESS PQ encryption".into(),
            ));
        }
        let pbk = reality_pbk.ok_or_else(|| {
            ProxyError::Config("missing REALITY 'pbk' public-key in vless:// URI".into())
        })?;
        if pbk != REDACTED_SECRET {
            decode_reality_public_key(&pbk).map_err(|_| {
                ProxyError::Config(
                    "invalid VLESS REALITY 'pbk' public-key (expected 32-byte Base64 X25519 key)"
                        .into(),
                )
            })?;
        }
        if let Some(ref sid) = reality_sid
            && sid != REDACTED_SECRET
        {
            decode_reality_short_id(sid).map_err(|_| {
                ProxyError::Config(
                    "invalid VLESS REALITY 'sid' short-id (expected 0..=16 hex digits)".into(),
                )
            })?;
        }
        skip_cert_verify = false;
        Some(RealityOptsConfig {
            public_key: pbk,
            short_id: reality_sid,
            spider_x: reality_spx,
        })
    } else {
        if reality_pbk.is_some() || reality_sid.is_some() || reality_spx.is_some() {
            return Err(ProxyError::Config(
                "VLESS REALITY parameter (pbk/sid/spx) requires security=reality".into(),
            ));
        }
        None
    };

    if let Some(ref vf) = flow {
        if net_type != "tcp" {
            return Err(ProxyError::Config(format!(
                "VLESS flow '{vf}' requires TCP transport (WebSocket is incompatible)"
            )));
        }
        if encryption != "none" {
            return Err(ProxyError::Config(format!(
                "VLESS flow '{vf}' cannot be combined with VLESS PQ encryption"
            )));
        }
        if !tls && reality_opts.is_none() {
            return Err(ProxyError::Config(format!(
                "VLESS flow '{vf}' requires security=tls or security=reality"
            )));
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
        reality_opts,
        client_fingerprint,
        network,
        ws_opts,
        udp,
    })
}

fn vmess_json_str(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    match obj.get(key)? {
        serde_json::Value::String(s) => Some(s.trim().to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn parse_vmess_uri(without_scheme: &str) -> Result<ProxyNodeConfig> {
    let (before_frag, fragment_opt) = match without_scheme.split_once('#') {
        Some((b, f)) => (b.trim(), Some(percent_decode_str(f))),
        None => (without_scheme.trim(), None),
    };
    let (authority_or_b64, _query_peek) = before_frag.split_once('?').unwrap_or((before_frag, ""));

    // v2rayN Base64-JSON format: `vmess://<base64_json>` (no `@` in authority)
    if !authority_or_b64.contains('@') {
        let unescaped = percent_decode_str(authority_or_b64.trim_end_matches('/'));
        let raw_bytes = decode_b64_flexible(&unescaped)
            .ok_or_else(|| ProxyError::Config("invalid Base64 payload in vmess:// URI".into()))?;
        let json_val: serde_json::Value = serde_json::from_slice(&raw_bytes)
            .map_err(|_| ProxyError::Config("invalid v2rayN JSON object in vmess:// URI".into()))?;
        let obj = json_val
            .as_object()
            .ok_or_else(|| ProxyError::Config("vmess:// JSON payload must be an object".into()))?;

        let server = vmess_json_str(obj, "add")
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim()
            .to_string();
        if server.is_empty() {
            return Err(ProxyError::Config(
                "missing 'add' server host in vmess:// JSON".into(),
            ));
        }
        let port_str = vmess_json_str(obj, "port").unwrap_or_default();
        let port: u16 = port_str.parse().map_err(|_| {
            ProxyError::Config(format!(
                "invalid 'port' '{}' in vmess:// JSON",
                safe_token_preview(&port_str)
            ))
        })?;
        if port == 0 {
            return Err(ProxyError::Config(
                "invalid port 0 in vmess:// JSON (must be 1..=65535)".into(),
            ));
        }
        let id_str = vmess_json_str(obj, "id").unwrap_or_default();
        let uuid = uuid::Uuid::parse_str(id_str.trim())
            .map_err(|_| ProxyError::Config("invalid VMess UUID 'id' in vmess:// JSON".into()))?;
        let alter_id: u16 = vmess_json_str(obj, "aid")
            .or_else(|| vmess_json_str(obj, "alterId"))
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u16>().unwrap_or(0))
            .unwrap_or(0);

        let cipher = vmess_json_str(obj, "scy")
            .or_else(|| vmess_json_str(obj, "cipher"))
            .or_else(|| vmess_json_str(obj, "security"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "auto".to_string());
        VmessSecurity::parse(&cipher).map_err(|_| {
            ProxyError::Config(format!(
                "unsupported VMess cipher '{}' in vmess:// JSON",
                safe_token_preview(&cipher)
            ))
        })?;

        let net_raw = vmess_json_str(obj, "net")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "tcp".to_string());
        let net_lc = net_raw.to_ascii_lowercase();
        let is_ws = match net_lc.as_str() {
            "tcp" | "raw" => false,
            "ws" | "websocket" => true,
            _ => {
                return Err(ProxyError::Config(format!(
                    "VMess transport '{}' is not supported (supported: tcp, ws)",
                    safe_token_preview(&net_raw)
                )));
            }
        };
        if !is_ws
            && let Some(obfs_type) = vmess_json_str(obj, "type")
            && !obfs_type.is_empty()
            && !obfs_type.eq_ignore_ascii_case("none")
        {
            return Err(ProxyError::Config(format!(
                "VMess TCP obfuscation header '{}' is not supported",
                safe_token_preview(&obfs_type)
            )));
        }

        let tls_str = vmess_json_str(obj, "tls").unwrap_or_default();
        let tls = matches!(tls_str.to_ascii_lowercase().as_str(), "tls" | "1" | "true");

        let host_field = vmess_json_str(obj, "host").filter(|s| !s.is_empty());
        let sni_field = vmess_json_str(obj, "sni")
            .or_else(|| vmess_json_str(obj, "servername"))
            .filter(|s| !s.is_empty());
        let servername = sni_field.or_else(|| {
            if tls && !is_ws {
                host_field.clone()
            } else {
                None
            }
        });

        let alpn = vmess_json_str(obj, "alpn")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let skip_cert_verify = vmess_json_str(obj, "allowInsecure")
            .or_else(|| vmess_json_str(obj, "insecure"))
            .or_else(|| vmess_json_str(obj, "skip-cert-verify"))
            .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true"));
        let global_padding = vmess_json_str(obj, "globalPadding")
            .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true"));
        let udp = !vmess_json_str(obj, "udp")
            .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "0" | "false"));

        let (network, ws_opts) = if is_ws {
            let mut headers = HashMap::new();
            if let Some(h) = host_field {
                headers.insert("Host".to_string(), h);
            }
            let path = vmess_json_str(obj, "path")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            (
                Some("ws".to_string()),
                Some(WsTransportConfig {
                    path,
                    headers,
                    max_early_data: None,
                    early_data_header_name: None,
                }),
            )
        } else {
            (None, None)
        };

        let name = fragment_opt
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .or_else(|| vmess_json_str(obj, "ps").filter(|s| !s.is_empty()))
            .unwrap_or_else(|| format!("VMess-{server}:{port}"));

        return Ok(ProxyNodeConfig::Vmess {
            name,
            server,
            port,
            uuid,
            alter_id,
            cipher,
            global_padding,
            tls,
            servername,
            skip_cert_verify,
            alpn,
            network,
            ws_opts,
            udp,
        });
    }

    // URI-style `vmess://uuid@host:port?...#Remark` or `vmess://<b64(cipher:uuid)>@host:port?...#Remark`
    let full_uri = format!("vmess://{without_scheme}");
    let parsed = Url::parse(&full_uri)
        .map_err(|_| ProxyError::Config("invalid vmess:// URI syntax".into()))?;
    let raw_user = extract_single_password_userinfo(&parsed);
    let mut cipher = "auto".to_string();
    let uuid = if let Ok(u) = uuid::Uuid::parse_str(raw_user.trim()) {
        u
    } else if let Some((c_str, u_str)) = raw_user.split_once(':')
        && let Ok(u) = uuid::Uuid::parse_str(u_str.trim())
    {
        cipher = c_str.trim().to_string();
        u
    } else if let Some(decoded) =
        decode_b64_flexible(&raw_user).and_then(|b| String::from_utf8(b).ok())
    {
        if let Ok(u) = uuid::Uuid::parse_str(decoded.trim()) {
            u
        } else if let Some((c_str, u_str)) = decoded.split_once(':')
            && let Ok(u) = uuid::Uuid::parse_str(u_str.trim())
        {
            cipher = c_str.trim().to_string();
            u
        } else {
            return Err(ProxyError::Config(
                "invalid VMess userinfo in vmess:// URI (expected 36-char UUID or Base64 cipher:uuid)"
                    .into(),
            ));
        }
    } else {
        return Err(ProxyError::Config(
            "invalid VMess userinfo in vmess:// URI (expected 36-char UUID or Base64 cipher:uuid)"
                .into(),
        ));
    };

    let server = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("missing host in vmess:// URI".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_string();
    if server.is_empty() {
        return Err(ProxyError::Config("missing host in vmess:// URI".into()));
    }
    let port = parsed
        .port()
        .ok_or_else(|| ProxyError::Config("missing port in vmess:// URI".into()))?;
    if port == 0 {
        return Err(ProxyError::Config(
            "invalid port 0 in vmess:// URI (must be 1..=65535)".into(),
        ));
    }

    let mut tls = false;
    let mut servername = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut net_type = "tcp".to_string();
    let mut ws_path: Option<String> = None;
    let mut ws_host: Option<String> = None;
    let mut ws_max_ed: Option<usize> = None;
    let mut ws_ed_hdr: Option<String> = None;
    let mut alter_id: u16 = 0;
    let mut global_padding = false;
    let mut udp = true;
    let mut remark_fallback = None;

    for (k, v) in raw_query_pairs(&parsed) {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "type" | "network" | "obfs" => match val_trimmed.to_ascii_lowercase().as_str() {
                "" | "tcp" | "raw" | "none" => net_type = "tcp".to_string(),
                "ws" | "websocket" => net_type = "ws".to_string(),
                _ => {
                    return Err(ProxyError::Config(format!(
                        "VMess transport '{}' is not supported (supported: tcp, ws)",
                        safe_token_preview(val_trimmed)
                    )));
                }
            },
            "encryption" | "cipher" | "scy" => {
                if !val_trimmed.is_empty() {
                    cipher = val_trimmed.to_string();
                }
            }
            "security" => match val_trimmed.to_ascii_lowercase().as_str() {
                "" | "none" => tls = false,
                "tls" => tls = true,
                other => {
                    if VmessSecurity::parse(other).is_ok() {
                        cipher = val_trimmed.to_string();
                    } else {
                        return Err(ProxyError::Config(format!(
                            "VMess security '{}' is not supported",
                            safe_token_preview(val_trimmed)
                        )));
                    }
                }
            },
            "tls" => {
                tls = matches!(
                    val_trimmed.to_ascii_lowercase().as_str(),
                    "1" | "true" | "tls"
                );
            }
            "sni" | "servername" | "peer" => {
                if !val_trimmed.is_empty() {
                    servername = Some(val_trimmed.to_string());
                }
            }
            "path" | "obfsparam" => {
                if !val_trimmed.is_empty() && val_trimmed.starts_with('/') {
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
                            "invalid VMess early-data size '{}'",
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
            "aid" | "alterid" | "alter-id" => {
                if let Ok(a) = val_trimmed.parse::<u16>() {
                    alter_id = a;
                }
            }
            "globalpadding" | "global-padding" => {
                global_padding = matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
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
            "udp" => {
                if matches!(val_trimmed.to_ascii_lowercase().as_str(), "0" | "false") {
                    udp = false;
                }
            }
            "remarks" | "remark" if !val_trimmed.is_empty() => {
                remark_fallback = Some(val_trimmed.to_string());
            }
            _ => {}
        }
    }

    VmessSecurity::parse(&cipher).map_err(|_| {
        ProxyError::Config(format!(
            "unsupported VMess cipher '{}'",
            safe_token_preview(&cipher)
        ))
    })?;

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

    let name = fragment_opt
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .or(remark_fallback)
        .unwrap_or_else(|| format!("VMess-{server}:{port}"));

    Ok(ProxyNodeConfig::Vmess {
        name,
        server,
        port,
        uuid,
        alter_id,
        cipher,
        global_padding,
        tls,
        servername,
        skip_cert_verify,
        alpn,
        network,
        ws_opts,
        udp,
    })
}

fn parse_hysteria2_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let normalized = normalize_single_password_uri(raw, "hysteria2://");
    let parsed = Url::parse(&normalized)
        .map_err(|_| ProxyError::Config("invalid hysteria2:// URI syntax".into()))?;
    let password = extract_single_password_userinfo(&parsed);
    if password.is_empty() {
        return Err(ProxyError::Config(
            "missing password in hysteria2:// URI".into(),
        ));
    }
    let server = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("missing host in hysteria2:// URI".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_string();
    if server.is_empty() {
        return Err(ProxyError::Config(
            "missing host in hysteria2:// URI".into(),
        ));
    }

    let explicit_port = parsed.port();
    if explicit_port == Some(0) {
        return Err(ProxyError::Config(
            "invalid port 0 in hysteria2:// URI (must be 1..=65535)".into(),
        ));
    }

    let mut ports: Option<String> = None;
    let mut obfs: Option<String> = None;
    let mut obfs_password: Option<String> = None;
    let mut up: Option<String> = None;
    let mut down: Option<String> = None;
    let mut sni: Option<String> = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut udp = true;
    let mut remark_fallback = None;

    for (k, v) in raw_query_pairs(&parsed) {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "sni" | "peer" | "servername" => {
                if !val_trimmed.is_empty() {
                    sni = Some(val_trimmed.to_string());
                }
            }
            "insecure" | "allowinsecure" | "skip-cert-verify" => {
                skip_cert_verify =
                    matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "obfs" => {
                if !val_trimmed.is_empty() && !val_trimmed.eq_ignore_ascii_case("none") {
                    if !val_trimmed.eq_ignore_ascii_case("salamander") {
                        return Err(ProxyError::Config(format!(
                            "Hysteria2 obfs '{}' is not supported (supported: salamander)",
                            safe_token_preview(val_trimmed)
                        )));
                    }
                    obfs = Some("salamander".to_string());
                }
            }
            "obfs-password" | "obfs_password" | "obfspassword" => {
                if !val_trimmed.is_empty() {
                    obfs_password = Some(val_trimmed.to_string());
                }
            }
            "mport" | "ports" => {
                if !val_trimmed.is_empty() {
                    ports = Some(val_trimmed.to_string());
                }
            }
            "up" | "upmbps" => {
                if !val_trimmed.is_empty() {
                    up = Some(val_trimmed.to_string());
                }
            }
            "down" | "downmbps" => {
                if !val_trimmed.is_empty() {
                    down = Some(val_trimmed.to_string());
                }
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
            "pinsha256" if !val_trimmed.is_empty() => {
                return Err(ProxyError::Config(
                    "Hysteria2 pinSHA256 certificate pinning is not supported".into(),
                ));
            }
            "remark" | "remarks" if !val_trimmed.is_empty() => {
                remark_fallback = Some(val_trimmed.to_string());
            }
            _ => {}
        }
    }

    let mut port = explicit_port.unwrap_or(443);
    if let Some(ref ps) = ports {
        let spec = PortSpec::parse(ps, port).map_err(|e| {
            ProxyError::Config(format!("invalid Hysteria2 mport specification: {e}"))
        })?;
        if explicit_port.is_none() {
            port = spec.first_port();
        }
    }

    if obfs.as_deref() == Some("salamander") {
        let pw = obfs_password.as_deref().unwrap_or("");
        if pw.is_empty() {
            return Err(ProxyError::Config(
                "Hysteria2 obfs=salamander requires non-empty obfs-password".into(),
            ));
        }
        if pw != REDACTED_SECRET {
            SalamanderObfs::new(pw)
                .map_err(|e| ProxyError::Config(format!("invalid Hysteria2 obfs-password: {e}")))?;
        }
    }

    parse_hy2_bandwidth_bytes_per_sec(up.as_deref())
        .map_err(|e| ProxyError::Config(format!("invalid Hysteria2 up bandwidth: {e}")))?;
    parse_hy2_bandwidth_bytes_per_sec(down.as_deref())
        .map_err(|e| ProxyError::Config(format!("invalid Hysteria2 down bandwidth: {e}")))?;

    let name = parsed
        .fragment()
        .map(percent_decode_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(remark_fallback)
        .unwrap_or_else(|| format!("Hy2-{server}:{port}"));

    Ok(ProxyNodeConfig::Hysteria2 {
        name,
        server,
        port,
        ports,
        password,
        obfs,
        obfs_password,
        up,
        down,
        sni,
        skip_cert_verify,
        alpn,
        udp,
    })
}

fn normalize_tuic_uri(raw: &str) -> String {
    let Some(rest) = raw.strip_prefix("tuic://") else {
        return raw.to_string();
    };
    let tail_idx = rest.find(['?', '#']).unwrap_or(rest.len());
    let (authority_and_path, suffix) = rest.split_at(tail_idx);
    let Some((raw_userinfo, hostport_and_path)) = authority_and_path.rsplit_once('@') else {
        return raw.to_string();
    };
    let (hostport, path_part) = match hostport_and_path.find('/') {
        Some(slash_idx) => hostport_and_path.split_at(slash_idx),
        None => (hostport_and_path, ""),
    };
    let unescaped_userinfo = percent_decode_str(raw_userinfo);
    let encoded_userinfo = if let Some((u, p)) = unescaped_userinfo.split_once(':') {
        format!(
            "{}:{}",
            percent_encode_component(u),
            percent_encode_component(p)
        )
    } else {
        percent_encode_component(&unescaped_userinfo)
    };
    format!("tuic://{encoded_userinfo}@{hostport}{path_part}{suffix}")
}

fn parse_tuic_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let normalized = normalize_tuic_uri(raw);
    let parsed = Url::parse(&normalized)
        .map_err(|_| ProxyError::Config("invalid tuic:// URI syntax".into()))?;
    let uuid_str = percent_decode_str(parsed.username());
    let uuid = uuid::Uuid::parse_str(uuid_str.trim()).map_err(|_| {
        ProxyError::Config(
            "invalid TUIC v5 UUID in tuic:// URI (expected uuid:password; legacy TUIC v4 token URIs are not supported)"
                .into(),
        )
    })?;
    let password = parsed
        .password()
        .map(percent_decode_str)
        .unwrap_or_default();

    let server = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("missing host in tuic:// URI".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_string();
    if server.is_empty() {
        return Err(ProxyError::Config("missing host in tuic:// URI".into()));
    }
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err(ProxyError::Config(
            "invalid port 0 in tuic:// URI (must be 1..=65535)".into(),
        ));
    }

    let mut udp_relay_mode: Option<String> = None;
    let mut congestion_controller: Option<String> = None;
    let mut reduce_rtt = false;
    let mut disable_sni = false;
    let mut heartbeat_interval: u64 = 10_000;
    let mut sni: Option<String> = None;
    let mut skip_cert_verify = false;
    let mut alpn = Vec::new();
    let mut udp = true;
    let mut remark_fallback = None;

    for (k, v) in raw_query_pairs(&parsed) {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "sni" | "servername" | "peer" => {
                if !val_trimmed.is_empty() {
                    sni = Some(val_trimmed.to_string());
                }
            }
            "alpn" => {
                alpn = val_trimmed
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "udp_relay_mode" | "udp-relay-mode" => {
                if !val_trimmed.is_empty() {
                    let mode = TuicUdpRelayMode::parse_opt(Some(val_trimmed)).map_err(|_| {
                        ProxyError::Config(format!(
                            "unsupported TUIC udp_relay_mode '{}' (expected native or quic)",
                            safe_token_preview(val_trimmed)
                        ))
                    })?;
                    udp_relay_mode = Some(mode.as_str().to_string());
                }
            }
            "congestion_control"
            | "congestion-control"
            | "congestion_controller"
            | "congestion-controller" => {
                if !val_trimmed.is_empty() {
                    let cc =
                        QuicCongestionControl::parse_opt(Some(val_trimmed)).map_err(|_| {
                            ProxyError::Config(format!(
                                "unsupported TUIC congestion_control '{}' (expected bbr, cubic, or new_reno)",
                                safe_token_preview(val_trimmed)
                            ))
                        })?;
                    congestion_controller = Some(cc.as_str().to_string());
                }
            }
            "reduce_rtt" | "reduce-rtt" | "zero_rtt_handshake" | "zero-rtt-handshake" => {
                reduce_rtt = matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "disable_sni" | "disable-sni" => {
                disable_sni = matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "heartbeat" | "heartbeat_interval" | "heartbeat-interval" => {
                let ht = val_trimmed.to_ascii_lowercase();
                if let Some(ms_part) = ht.strip_suffix("ms") {
                    if let Ok(ms) = ms_part.trim().parse::<u64>() {
                        heartbeat_interval = ms;
                    }
                } else if let Some(sec_part) = ht.strip_suffix('s') {
                    if let Ok(secs) = sec_part.trim().parse::<u64>() {
                        heartbeat_interval = secs.saturating_mul(1000);
                    }
                } else if let Ok(ms) = ht.parse::<u64>() {
                    heartbeat_interval = ms;
                }
            }
            "allow_insecure" | "allowinsecure" | "insecure" | "skip-cert-verify" => {
                skip_cert_verify =
                    matches!(val_trimmed.to_ascii_lowercase().as_str(), "1" | "true");
            }
            "udp" => {
                if matches!(val_trimmed.to_ascii_lowercase().as_str(), "0" | "false") {
                    udp = false;
                }
            }
            "remark" | "remarks" if !val_trimmed.is_empty() => {
                remark_fallback = Some(val_trimmed.to_string());
            }
            _ => {}
        }
    }

    let name = parsed
        .fragment()
        .map(percent_decode_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(remark_fallback)
        .unwrap_or_else(|| format!("TUIC-{server}:{port}"));

    Ok(ProxyNodeConfig::Tuic {
        name,
        server,
        port,
        uuid,
        password,
        udp_relay_mode,
        congestion_controller,
        reduce_rtt,
        disable_sni,
        heartbeat_interval,
        sni,
        skip_cert_verify,
        alpn,
        udp,
    })
}

/// Normalize single-credential share URIs (`trojan://password@host:port`, `anytls://password@host:port`)
/// where real-world panels emit raw unencoded `@`, `:`, or `/` characters inside `password`.
fn normalize_single_password_uri(raw: &str, scheme_prefix: &str) -> String {
    let Some(rest) = raw.strip_prefix(scheme_prefix) else {
        return raw.to_string();
    };
    let tail_idx = rest.find(['?', '#']).unwrap_or(rest.len());
    let (authority_and_path, suffix) = rest.split_at(tail_idx);
    let Some((raw_pass, hostport_and_path)) = authority_and_path.rsplit_once('@') else {
        return raw.to_string();
    };
    let (hostport, path_part) = match hostport_and_path.find('/') {
        Some(slash_idx) => hostport_and_path.split_at(slash_idx),
        None => (hostport_and_path, ""),
    };
    let decoded_pass = percent_decode_str(raw_pass);
    let encoded_pass = percent_encode_component(&decoded_pass);
    format!("{scheme_prefix}{encoded_pass}@{hostport}{path_part}{suffix}")
}

fn extract_single_password_userinfo(parsed: &Url) -> String {
    match parsed.password() {
        Some(p) => format!(
            "{}:{}",
            percent_decode_str(parsed.username()),
            percent_decode_str(p)
        ),
        None => percent_decode_str(parsed.username()),
    }
}

fn parse_trojan_uri(raw: &str) -> Result<ProxyNodeConfig> {
    let normalized = normalize_single_password_uri(raw, "trojan://");
    let parsed = Url::parse(&normalized)
        .map_err(|_| ProxyError::Config("invalid trojan:// URI syntax".into()))?;
    let password = extract_single_password_userinfo(&parsed);
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

    for (k, v) in raw_query_pairs(&parsed) {
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
            let unescaped_user = percent_decode_str(userinfo);
            let (u, p) = if let Some((u_enc, p_enc)) = userinfo.split_once(':') {
                (
                    Some(percent_decode_str(u_enc)),
                    Some(percent_decode_str(p_enc)),
                )
            } else if let Some(decoded) =
                decode_b64_flexible(&unescaped_user).and_then(|b| String::from_utf8(b).ok())
                && let Some((u_dec, p_dec)) = decoded.split_once(':')
            {
                (Some(u_dec.to_string()), Some(p_dec.to_string()))
            } else {
                (Some(unescaped_user), None)
            };
            let (host, port) = split_host_port(hostport)?;
            (u.filter(|s| !s.is_empty()), p, host, port)
        } else if !main_part.contains(':')
            && let Some(decoded) = decode_b64_flexible(&percent_decode_str(main_part))
                .and_then(|b| String::from_utf8(b).ok())
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
    let normalized = normalize_single_password_uri(raw, "anytls://");
    let parsed = Url::parse(&normalized)
        .map_err(|_| ProxyError::Config("invalid anytls:// URI syntax".into()))?;
    let password = extract_single_password_userinfo(&parsed);
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
    let mut remark_fallback = None;

    for (k, v) in raw_query_pairs(&parsed) {
        let key_lower = k.trim().to_ascii_lowercase();
        let val_trimmed = v.trim();
        match key_lower.as_str() {
            "sni" | "peer" | "servername" => {
                if !val_trimmed.is_empty() {
                    sni = Some(val_trimmed.to_string());
                }
            }
            "insecure" | "allowinsecure" | "skip-cert-verify" => {
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
            "pbk" | "publickey" | "sid" | "shortid" | "spx" | "servicename" => {
                if !val_trimmed.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "AnyTLS parameter '{}' is not supported",
                        safe_token_preview(&k)
                    )));
                }
            }
            "remark" | "remarks" if !val_trimmed.is_empty() => {
                remark_fallback = Some(val_trimmed.to_string());
            }
            _ => {}
        }
    }
    let name = parsed
        .fragment()
        .map(percent_decode_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(remark_fallback)
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
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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
            reality_opts: None,
            client_fingerprint: None,
            network: None,
            ws_opts: None,
            udp: true,
        };
        let vless_uri = export_proxy_uri(&vless);
        let parsed_vless = parse_proxy_uri(&vless_uri).unwrap();
        assert_eq!(parsed_vless.name(), "Tokyo VLESS PQ");

        // VLESS + REALITY + Vision roundtrip
        let reality_pbk = URL_SAFE_NO_PAD.encode([0x5au8; 32]);
        let vless_reality_raw = format!(
            "vless://12345678-1234-4321-abcd-998877665544@reality.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={reality_pbk}&sid=01ab23cd&spx=%2Flogin#JP-REALITY-Vision"
        );
        let parsed_reality = parse_proxy_uri(&vless_reality_raw).unwrap();
        assert_eq!(parsed_reality.protocol_label(), "VLESS+REALITY+Vision");
        let reparsed_reality = parse_proxy_uri(&export_proxy_uri(&parsed_reality)).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed_reality).unwrap(),
            serde_json::to_value(&reparsed_reality).unwrap()
        );
        assert_eq!(
            proxy_node_dedup_key(&parsed_reality),
            proxy_node_dedup_key(&reparsed_reality)
        );

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

        // VMess v2rayN Base64-JSON & URI-style roundtrips
        let vmess_ws = ProxyNodeConfig::Vmess {
            name: "TW VMess WS".into(),
            server: "tw.example.com".into(),
            port: 443,
            uuid: uuid::Uuid::parse_str("12345678-1234-4321-abcd-998877665544").unwrap(),
            alter_id: 0,
            cipher: "chacha20-poly1305".into(),
            global_padding: false,
            tls: true,
            servername: Some("tw.example.com".into()),
            skip_cert_verify: false,
            alpn: vec!["h2".into(), "http/1.1".into()],
            network: Some("ws".into()),
            ws_opts: Some(WsTransportConfig {
                path: "/vmess-ws".into(),
                headers: HashMap::from([("Host".into(), "cdn.tw.example.com".into())]),
                max_early_data: None,
                early_data_header_name: None,
            }),
            udp: true,
        };
        assert_eq!(vmess_ws.protocol_label(), "VMess+WS");
        let vmess_uri = export_proxy_uri(&vmess_ws);
        assert!(vmess_uri.starts_with("vmess://"));
        let reparsed_vmess = parse_proxy_uri(&vmess_uri).unwrap();
        assert_eq!(reparsed_vmess.name(), "TW VMess WS");
        assert_eq!(reparsed_vmess.protocol_label(), "VMess+WS");
        assert_eq!(
            proxy_node_dedup_key(&vmess_ws),
            proxy_node_dedup_key(&reparsed_vmess)
        );

        let vmess_std_uri = "vmess://12345678-1234-4321-abcd-998877665544@vm.example.com:8443?encryption=aes-128-gcm&security=tls&sni=vm.example.com&type=ws&path=%2Fv2&host=vm.example.com#URI-VMess";
        let parsed_vmess_std = parse_proxy_uri(vmess_std_uri).unwrap();
        assert_eq!(parsed_vmess_std.name(), "URI-VMess");
        assert_eq!(parsed_vmess_std.protocol_label(), "VMess+WS");

        // Hysteria2 (`hy2://` with Salamander obfs + mport) roundtrip
        let hy2_raw = "hy2://s3cr3t%40pass@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=obfs-k3y&mport=20000-20100&upmbps=50&downmbps=200&insecure=1#KR-Hysteria2";
        let parsed_hy2 = parse_proxy_uri(hy2_raw).unwrap();
        assert_eq!(parsed_hy2.protocol_label(), "Hysteria2");
        assert_eq!(parsed_hy2.name(), "KR-Hysteria2");
        let reparsed_hy2 = parse_proxy_uri(&export_proxy_uri(&parsed_hy2)).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed_hy2).unwrap(),
            serde_json::to_value(&reparsed_hy2).unwrap()
        );
        assert_eq!(
            proxy_node_dedup_key(&parsed_hy2),
            proxy_node_dedup_key(&reparsed_hy2)
        );

        // TUIC v5 (`tuic://uuid:password@host:port`) roundtrip
        let tuic_raw = "tuic://12345678-1234-4321-abcd-998877665544:tuic%3Ap%40ss@tuic.example.com:8443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=tuic.example.com&reduce_rtt=1#SG-TUICv5";
        let parsed_tuic = parse_proxy_uri(tuic_raw).unwrap();
        assert_eq!(parsed_tuic.protocol_label(), "TUIC-v5");
        assert_eq!(parsed_tuic.name(), "SG-TUICv5");
        let reparsed_tuic = parse_proxy_uri(&export_proxy_uri(&parsed_tuic)).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed_tuic).unwrap(),
            serde_json::to_value(&reparsed_tuic).unwrap()
        );
        assert_eq!(
            proxy_node_dedup_key(&parsed_tuic),
            proxy_node_dedup_key(&reparsed_tuic)
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
    fn strict_rejects_grpc_invalid_reality_legacy_flow_and_malformed_uris_without_leaking_secrets()
    {
        let secret_uuid = "12345678-1234-4321-abcd-998877665544";
        let bad_reality_pbk = "SUPER_SECRET_REALITY_PBK_VALUE_XYZ";

        for (uri, expected_substr) in [
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=tls&type=grpc&serviceName=gun#gRPC-Node"
                ),
                "VLESS transport 'grpc' is not supported",
            ),
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=reality&pbk={bad_reality_pbk}&sid=01ab#Bad-Reality-PBK"
                ),
                "invalid VLESS REALITY 'pbk' public-key",
            ),
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=tls&flow=xtls-rprx-direct#Legacy-Xtls-Node"
                ),
                "VLESS flow",
            ),
            (
                format!(
                    "vless://{secret_uuid}@edge.example.com:443?encryption=none&security=tls&pbk={bad_reality_pbk}#Sneaky-PBK"
                ),
                "VLESS REALITY parameter",
            ),
            (
                "trojan://MY_ULTRA_SECRET_TROJAN_PASS@host.example.com:443?type=grpc&serviceName=gun#Trojan-gRPC"
                    .to_string(),
                "Trojan transport 'grpc' is not supported",
            ),
            (
                "vmess://MY_ULTRA_SECRET_VMESS_PAYLOAD@host.example.com:443#Bad-VMess".to_string(),
                "invalid VMess userinfo in vmess:// URI",
            ),
            (
                "tuic://MY_ULTRA_SECRET_TUIC_V4_TOKEN@host.example.com:443#TUICv4".to_string(),
                "invalid TUIC v5 UUID",
            ),
            (
                "ssr://MY_ULTRA_SECRET_SSR_PAYLOAD@host.example.com:8388#SSR".to_string(),
                "unsupported proxy URI scheme 'ssr://'",
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
                !safe_err.contains(bad_reality_pbk),
                "REALITY pbk leaked in error message: {safe_err}"
            );
            assert!(
                !safe_err.contains("MY_ULTRA_SECRET_TROJAN_PASS")
                    && !safe_err.contains("MY_ULTRA_SECRET_VMESS_PAYLOAD")
                    && !safe_err.contains("MY_ULTRA_SECRET_TUIC_V4_TOKEN")
                    && !safe_err.contains("MY_ULTRA_SECRET_SSR_PAYLOAD"),
                "password leaked in error message: {safe_err}"
            );
        }
    }

    #[test]
    fn mixed_subscription_uris_best_effort_skips_unsupported_and_fails_closed_when_zero_valid() {
        let mixed = "\
trojan://pass123@tj.example.com:443?sni=tj.example.com#HK-Trojan\n\
hy2://hy2pass@hy2.example.com:443?sni=hy2.example.com#SG-Hysteria2\n\
vmess://SECRET_VMESS_TOKEN@vm.example.com:443#JP-Bad-VMess\n\
ssr://SECRET_SSR_PASS@ssr.example.com:8388#KR-SSR\n\
socks5://127.0.0.1:1080#Local-Socks\n";
        let (nodes, skipped) = parse_subscription_uris_best_effort(mixed).unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0].name, "JP-Bad-VMess");
        assert_eq!(skipped[0].protocol, "vmess");
        assert!(!skipped[0].reason.contains("SECRET_VMESS_TOKEN"));
        assert!(!skipped[1].reason.contains("SECRET_SSR_PASS"));

        let all_unsupported = "vmess://SECRET_VMESS_TOKEN@vm.example.com:443#Only-Bad-VMess\nssr://SECRET_SSR_PASS@ssr.example.com:8388#Only-SSR";
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

    #[test]
    fn redact_sensitive_text_scrubs_sub_titles_and_ip_literal_urls_while_preserving_loopback_and_domains()
     {
        let sub_ip_title = redact_sensitive_text("Auto-updated profile 'Sub (203.0.113.124)'");
        assert_eq!(sub_ip_title, "Auto-updated profile 'Sub (***REDACTED***)'");
        assert!(!sub_ip_title.contains("203.0.113.124"));

        let sub_domain_title = redact_sensitive_text("Sub (sub.provider.com)");
        assert_eq!(sub_domain_title, "Sub (***REDACTED***)");
        assert!(!sub_domain_title.contains("sub.provider.com"));

        let ip_url = redact_sensitive_text("fetch https://203.0.113.124:8443/sub?token=abc failed");
        assert_eq!(ip_url, "fetch https://***REDACTED*** failed");
        assert!(!ip_url.contains("203.0.113.124"));
        assert!(!ip_url.contains("abc"));
        // Verify idempotency when redacted twice
        assert_eq!(redact_sensitive_text(&ip_url), ip_url);

        let ipv6_url =
            redact_sensitive_text("fetch https://[2400:3200::1]:8443/sub?token=abc failed");
        assert_eq!(ipv6_url, "fetch https://***REDACTED*** failed");
        assert!(!ipv6_url.contains("2400:3200::1"));

        let loopback_url = redact_sensitive_text("http://127.0.0.1:18080/sub?token=abc");
        assert_eq!(loopback_url, "http://127.0.0.1:18080/***REDACTED***");

        let domain_url = redact_sensitive_text("https://sub.example.com:8443/sub?token=abc");
        assert_eq!(domain_url, "https://sub.example.com:8443/***REDACTED***");
    }

    #[test]
    fn uri_edge_cases_preserve_slash_passwords_plus_queries_percent_b64_socks5h_and_udp_false() {
        // 1. Trojan/AnyTLS raw Base64 password containing '/' and '@'
        let trojan_slash = "trojan://aGVsbG8/d29ybGQ=@tj.example.com:443?type=ws&path=%2Fws+v2&ed=2048&earlyDataHeaderName=X-Early-Data&udp=0#Slash-Pass";
        let tj = parse_proxy_uri(trojan_slash).expect("trojan with '/' in password");
        match &tj {
            ProxyNodeConfig::Trojan {
                password,
                udp,
                ws_opts,
                ..
            } => {
                assert_eq!(password, "aGVsbG8/d29ybGQ=");
                assert!(!*udp);
                let ws = ws_opts.as_ref().unwrap();
                assert_eq!(ws.path, "/ws+v2");
                assert_eq!(ws.early_data_header_name.as_deref(), Some("X-Early-Data"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        let re_tj = parse_proxy_uri(&export_proxy_uri(&tj)).unwrap();
        assert_eq!(
            serde_json::to_value(&tj).unwrap(),
            serde_json::to_value(&re_tj).unwrap()
        );

        // 2. VLESS & AnyTLS udp=0 export/import roundtrip + literal '+' in query path
        let vless_no_udp = parse_proxy_uri(
            "vless://12345678-1234-4321-abcd-998877665544@edge.example.com:443?type=ws&security=tls&path=/a+b&udp=0#VL-NoUDP",
        )
        .unwrap();
        let re_vl = parse_proxy_uri(&export_proxy_uri(&vless_no_udp)).unwrap();
        assert_eq!(
            serde_json::to_value(&vless_no_udp).unwrap(),
            serde_json::to_value(&re_vl).unwrap()
        );

        let anytls_no_udp = parse_proxy_uri(
            "anytls://p/ass+word=@at.example.com:443?sni=at.example.com&udp=0#AT-NoUDP",
        )
        .unwrap();
        let re_at = parse_proxy_uri(&export_proxy_uri(&anytls_no_udp)).unwrap();
        assert_eq!(
            serde_json::to_value(&anytls_no_udp).unwrap(),
            serde_json::to_value(&re_at).unwrap()
        );

        // 3. Percent-encoded Base64 userinfo in ss:// and socks5h://
        let ss_userinfo = STANDARD.encode("aes-256-gcm:sec+ret/key=");
        let pct_ss_userinfo = ss_userinfo
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let parsed_ss =
            parse_proxy_uri(&format!("ss://{pct_ss_userinfo}@1.2.3.4:8388#Pct-SS")).unwrap();
        match parsed_ss {
            ProxyNodeConfig::Ss { password, .. } => assert_eq!(password, "sec+ret/key="),
            other => panic!("unexpected: {other:?}"),
        }

        let socks5h = parse_proxy_uri("socks5h://user:pass@10.0.0.8:1080#Socks5h").unwrap();
        assert_eq!(socks5h.protocol_label(), "SOCKS5");
        assert!(
            redact_sensitive_text("socks5h://user:pass@10.0.0.8:1080").contains(REDACTED_SECRET)
        );

        let http_std = parse_proxy_uri("http://alice:secret@10.0.0.9:8080#Std-HTTP").unwrap();
        assert_eq!(http_std.protocol_label(), "HTTP");
        assert!(
            parse_proxy_uri("https://sub.example.com:8443/api/v1/client/subscribe?token=abc")
                .is_err(),
            "subscription URLs with subpaths must not parse as HTTP proxy nodes"
        );
    }

    #[test]
    fn redact_sensitive_text_preserves_escaped_delimiters_without_leaking_backslash_secrets() {
        // 1. JSON-escaped IP DoH, IPv6 DoH, authenticated URL, and proxy URI preserve `\"`
        let cases = [
            (
                r#"\"https://223.5.5.5/dns-query\""#,
                r#"\"https://***REDACTED***\""#,
                &["223.5.5.5", "dns-query"][..],
            ),
            (
                r#"\"https://[2400:3200::1]:8443/dns-query\""#,
                r#"\"https://***REDACTED***\""#,
                &["2400:3200::1", "dns-query"][..],
            ),
            (
                r#"\"https://user:pass@host.example/path?k=v&token=abc\""#,
                r#"\"https://host.example/***REDACTED***\""#,
                &["user", "pass", "token", "abc"][..],
            ),
            (
                r#"\"vless://12345678-1234-4321-abcd-998877665544@host:443?pbk=xyz#tag\""#,
                r#"\"vless://***REDACTED***\""#,
                &["12345678-1234-4321-abcd-998877665544", "xyz", "tag"][..],
            ),
            // 2. Double-escaped JSON and trailing literal backslash inside JSON string
            (
                r#"\\\"https://223.5.5.5/dns-query\\\""#,
                r#"\\\"https://***REDACTED***\\\""#,
                &["223.5.5.5", "dns-query"][..],
            ),
            (
                r#""https://223.5.5.5/dns-query\\""#,
                r#""https://***REDACTED***\\""#,
                &["223.5.5.5", "dns-query"][..],
            ),
            // 3. key=val and PQ key with escaped closing quote (and extra delimiters)
            (
                r#"key=secretval\"tail"#,
                r#"key=***REDACTED***\"tail"#,
                &["secretval"][..],
            ),
            (
                r#"mlkem768x25519plus.native.0rtt.SECRET\"tail"#,
                r#"mlkem768x25519plus.***REDACTED***\"tail"#,
                &["SECRET", "0rtt"][..],
            ),
            (
                r#"mlkem768x25519plus.native.0rtt.SECRET,next;after>end"#,
                r#"mlkem768x25519plus.***REDACTED***,next;after>end"#,
                &["SECRET"][..],
            ),
            (
                r#"key=secretval>tail"#,
                r#"key=***REDACTED***>tail"#,
                &["secretval"][..],
            ),
            (
                r#"key=secretval\&other=1"#,
                r#"key=***REDACTED***\&other=1"#,
                &["secretval"][..],
            ),
            // 4. Raw credentials containing backslashes and JSON-escaped `\/` — ZERO leak!
            (
                r#"trojan://my\secret@edge.example:443"#,
                "trojan://***REDACTED***",
                &["my", "secret", "edge.example"][..],
            ),
            (
                r#"https://user:p\ass@edge.example/sub?token=abc"#,
                "***REDACTED_URL***",
                &["user", "p\\ass", "ass", "edge.example", "token", "abc"][..],
            ),
            (
                r#"password=my\secret123"#,
                "password=***REDACTED***",
                &["my", "secret123"][..],
            ),
            (
                r#"https://sub.example.com/api\/secret_token"#,
                "https://sub.example.com/***REDACTED***",
                &["api", "secret_token"][..],
            ),
            // 5. Windows path adjacent to URL
            (
                r#"failed https://sub.example.com/sub?token=abc in C:\Users\alice\cfg.yaml"#,
                r#"failed https://sub.example.com/***REDACTED*** in C:\Users\alice\cfg.yaml"#,
                &["token", "abc"][..],
            ),
            // 6. Pass 5 escaped quotes inside serde string literals & even backslashes before close
            (
                r#"invalid value: string "my\"secret", expected map"#,
                r#"invalid value: string "***REDACTED***", expected map"#,
                &["my", "secret"][..],
            ),
            (
                r#"invalid value: string "trailing\\", expected map"#,
                r#"invalid value: string "***REDACTED***", expected map"#,
                &["trailing"][..],
            ),
            (
                r#"invalid value: string 'my\'secret', expected map"#,
                r#"invalid value: string '***REDACTED***', expected map"#,
                &["my", "secret"][..],
            ),
            (
                r#"invalid value: string `my\`secret`, expected map"#,
                r#"invalid value: string `***REDACTED***`, expected map"#,
                &["my", "secret"][..],
            ),
        ];

        for (input, expected, forbidden) in cases {
            let redacted = redact_sensitive_text(input);
            assert_eq!(
                redacted, expected,
                "unexpected redaction for input: {input}"
            );
            for secret in forbidden {
                assert!(
                    !redacted.contains(secret),
                    "secret '{secret}' leaked in '{redacted}' (from '{input}')"
                );
            }
            // Idempotency invariant
            assert_eq!(
                redact_sensitive_text(&redacted),
                redacted,
                "redact_sensitive_text must be idempotent for input: {input}"
            );
        }

        // Verify JSON string containing Debug-formatted DoH URLs stays valid JSON after redaction
        let debug_diff_json = serde_json::to_string(
            r#"dns.nameserver: ["223.5.5.5:53", "https://223.5.5.5/dns-query", "https://[2400:3200::1]:8443/dns-query"]"#,
        )
        .unwrap();
        let redacted_json = redact_sensitive_text(&debug_diff_json);
        let reparsed: String =
            serde_json::from_str(&redacted_json).expect("redacted JSON string must remain valid");
        assert!(
            reparsed.contains("https://***REDACTED***"),
            "DoH URLs must be redacted: {reparsed}"
        );
        assert!(
            !reparsed.contains("https://223.5.5.5") && !reparsed.contains("2400:3200::1"),
            "DoH IP literals must not leak: {reparsed}"
        );
        assert_eq!(redact_sensitive_text(&redacted_json), redacted_json);

        // Trailing backslash at EOF
        let eof_bs = redact_sensitive_text(r#"https://223.5.5.5/dns-query\"#);
        assert_eq!(eof_bs, r#"https://***REDACTED***\"#);
        assert_eq!(redact_sensitive_text(&eof_bs), eof_bs);
    }

    #[test]
    fn redact_sensitive_text_handles_long_backslash_runs_in_linear_time() {
        let bs = "\\".repeat(50_000);
        let uri_input = format!("https://example.com/{bs}x");
        let pq_input = format!("mlkem768x25519plus.{bs}x");
        let kv_input = format!("token={bs}x");

        let started = std::time::Instant::now();
        assert_eq!(
            redact_sensitive_text(&uri_input),
            "https://example.com/***REDACTED***"
        );
        assert_eq!(
            redact_sensitive_text(&pq_input),
            "mlkem768x25519plus.***REDACTED***"
        );
        assert_eq!(redact_sensitive_text(&kv_input), "token=***REDACTED***");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "50k-backslash redaction must run in linear O(N) time, took {elapsed:?}"
        );
    }

    #[test]
    fn redact_url_inline_blocks_whatwg_backslash_before_at_credential_leak() {
        let leak_vectors: [(&str, &[&str]); 9] = [
            (
                r#"https://secretuser:8080\mypass@host.example/x"#,
                &["secretuser", "8080", "mypass", "host.example"],
            ),
            (
                r#"https://mysecretuser\mypass@host.example/x"#,
                &["mysecretuser", "mypass", "host.example"],
            ),
            (
                r#"https://secret_token\foo@203.0.113.5/x"#,
                &["secret_token", "foo", "203.0.113.5"],
            ),
            (
                r#"https://mysecret:\mypass@host.example/x"#,
                &["mysecret", "mypass", "host.example"],
            ),
            (
                r#"https://user\/pass@sub.example.com/api"#,
                &["user", "pass", "sub.example.com"],
            ),
            (
                r#"https://127.0.0.1:8080\secret@203.0.113.5/x"#,
                &["127.0.0.1", "8080", "secret", "203.0.113.5"],
            ),
            (
                r#"http://secret_user:80\pass@example.com/sub"#,
                &["secret_user", "80", "pass", "example.com"],
            ),
            (
                r#"https:///secretuser\mypass@host.example/x"#,
                &["secretuser", "mypass", "host.example"],
            ),
            (
                r#"https://alice@corp.local\secret@host.example/x"#,
                &["alice", "corp.local", "secret", "host.example"],
            ),
        ];

        for (input, forbidden) in leak_vectors {
            let redacted = redact_sensitive_text(input);
            assert_eq!(
                redacted, "***REDACTED_URL***",
                "backslash-before-@ URL must fail closed: {input}"
            );
            for secret in forbidden {
                assert!(
                    !redacted.contains(secret),
                    "credential/host fragment '{secret}' leaked in '{redacted}' (from '{input}')"
                );
            }
            assert_eq!(redact_sensitive_text(&redacted), redacted);
        }

        // JSON-escaped `\/` in path AFTER `@` (or without `@`) still preserves safe host and redacts path/credentials
        let auth_json_path =
            redact_sensitive_text(r#"https://user:pass@sub.example.com\/api\/secret"#);
        assert_eq!(auth_json_path, "https://sub.example.com/***REDACTED***");
        assert!(!auth_json_path.contains("user") && !auth_json_path.contains("pass"));
        assert!(!auth_json_path.contains("secret"));
        assert_eq!(redact_sensitive_text(&auth_json_path), auth_json_path);

        let plain_json_path =
            redact_sensitive_text(r#"https://sub.example.com\/api\/secret_token"#);
        assert_eq!(plain_json_path, "https://sub.example.com/***REDACTED***");
        assert!(!plain_json_path.contains("secret_token"));
        assert_eq!(redact_sensitive_text(&plain_json_path), plain_json_path);
    }

    #[test]
    fn has_backslash_before_at_and_redact_sensitive_text_block_whatwg_tab_cr_lf_bypasses() {
        let whatwg_ws_vectors: [(&str, &[&str]); 5] = [
            (
                "https://\t/tabsecuser:8080\\tabsecpass@doh.example/dns-query",
                &["tabsecuser", "8080", "tabsecpass", "doh.example"],
            ),
            (
                "https://\n/lfsecuser:8080\\lfsecpass@doh.example/dns-query",
                &["lfsecuser", "8080", "lfsecpass", "doh.example"],
            ),
            (
                "https://\r/crsecuser:8080\\crsecpass@doh.example/dns-query",
                &["crsecuser", "8080", "crsecpass", "doh.example"],
            ),
            (
                "https:///\t/stsecuser:8080\\stsecpass@doh.example/dns-query",
                &["stsecuser", "8080", "stsecpass", "doh.example"],
            ),
            (
                "https://\t/tabquser:8080\\tabqpass@doh.example/dns-query?token=TabQTok",
                &["tabquser", "8080", "tabqpass", "doh.example", "TabQTok"],
            ),
        ];

        for (input, forbidden) in whatwg_ws_vectors {
            assert!(
                has_backslash_before_at_in_authority(input),
                "has_backslash_before_at_in_authority must detect WHATWG tab/CR/LF bypass: {input:?}"
            );
            let redacted = redact_sensitive_text(input);
            assert_eq!(
                redacted, "***REDACTED_URL***",
                "redact_sensitive_text must fail closed on WHATWG tab/CR/LF backslash URL: {input:?}"
            );
            for secret in forbidden {
                assert!(
                    !redacted.contains(secret),
                    "secret '{secret}' leaked in '{redacted}' (from '{input:?}')"
                );
            }
            assert_eq!(redact_sensitive_text(&redacted), redacted);
        }

        // Scheme-embedded tab before `://` is also caught by `has_backslash_before_at_in_authority`
        assert!(has_backslash_before_at_in_authority(
            "https:\t//tabschemeuser:8080\\tabschemepass@doh.example/dns-query"
        ));

        // Benign multi-line and TSV logs around bare schemes or clean URLs are not over-swallowed
        assert_eq!(
            redact_sensitive_text("expected https://\nnext line"),
            "expected https://\nnext line"
        );
        assert_eq!(
            redact_sensitive_text("url:\thttps://example.com/a\tstatus=200"),
            "url:\thttps://example.com/***REDACTED***\tstatus=200"
        );
        assert_eq!(
            redact_sensitive_text("http://\thttps://example.com/a"),
            "http://\thttps://example.com/***REDACTED***"
        );

        // Authorization Bearer / Basic header scrubbing without breaking benign prose
        assert_eq!(
            redact_sensitive_text("Authorization: Bearer SuperSecret99"),
            "Authorization: Bearer ***REDACTED***"
        );
        assert_eq!(
            redact_sensitive_text("Proxy-Authorization: Basic dXNlcjpwYXNz"),
            "Proxy-Authorization: Basic ***REDACTED***"
        );
        assert_eq!(
            redact_sensitive_text("Elevated TUN helper listening (Bearer secret active)"),
            "Elevated TUN helper listening (Bearer secret active)"
        );
    }

    #[test]
    fn redact_sensitive_text_handles_dot_doq_doh3_schemes_idempotently() {
        // Clean bare DoT/DoQ/DoH3 upstreams remain readable and idempotent
        for clean in [
            "tls://1.1.1.1:853",
            "tls://dot.example.com:853",
            "tls://dot.example.com:853/",
            "tls://[2001:db8::1]:853",
            "quic://1.1.1.1:853",
            "h3://dns.google",
            "doq://1.1.1.1:853",
        ] {
            let r1 = redact_sensitive_text(clean);
            assert_eq!(r1, clean, "clean DNS transport URL should remain intact");
            assert_eq!(redact_sensitive_text(&r1), r1);
        }

        // Authenticated / query / fragment / private-path DoT/DoQ/DoH3 redact tails cleanly
        let redacted_cases: [(&str, &str, &[&str]); 7] = [
            (
                "tls://dotuser:DotPassSecret99@dot.corp.example:853/DotPathSecret88",
                "tls://dot.corp.example:853/***REDACTED***",
                &["dotuser", "DotPassSecret99", "DotPathSecret88"],
            ),
            (
                "TLS://dotuser:UpperDotPass@dot.corp.example:853/UpperDotPath",
                "tls://dot.corp.example:853/***REDACTED***",
                &["dotuser", "UpperDotPass", "UpperDotPath"],
            ),
            (
                "quic://quicuser:QuicPassSecret77@doq.corp.example:853/QuicPathSecret66",
                "quic://doq.corp.example:853/***REDACTED***",
                &["quicuser", "QuicPassSecret77", "QuicPathSecret66"],
            ),
            (
                "h3://h3user:H3PassSecret55@h3.corp.example/H3PathSecret44",
                "h3://h3.corp.example/***REDACTED***",
                &["h3user", "H3PassSecret55", "H3PathSecret44"],
            ),
            (
                "doq://doquser:DoqPass@doq.corp.example:853?tok=DoqTok#frag",
                "doq://doq.corp.example:853/***REDACTED***",
                &["doquser", "DoqPass", "DoqTok", "frag"],
            ),
            (
                "tls://1.1.1.1:853#sni=SecretSniHost.corp",
                "tls://1.1.1.1:853/***REDACTED***",
                &["SecretSniHost"],
            ),
            (
                "tls://dot.corp.example:853/SecretSeg/../",
                "tls://dot.corp.example:853/***REDACTED***",
                &["SecretSeg"],
            ),
        ];
        for (input, expected, forbidden) in redacted_cases {
            let r1 = redact_sensitive_text(input);
            assert_eq!(r1, expected, "unexpected redaction for {input}");
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(
                redact_sensitive_text(&r1),
                r1,
                "must be idempotent: {input}"
            );
        }

        // Malformed / backslash / empty-host / tab DoT/DoQ/DoH3 fail closed
        for fail_closed in [
            "tls://dotuser:ActiveDotErrPass@dot.corp.example:99999/ActiveDotErrPath",
            "tls:///emptyhost/SecretPath",
            r"tls://dot.corp.example\BackslashSecret",
            r"tls://dotuser:8080\DotBsPass@dot.corp.example:853/dns",
            "tls://\t/dotuser:TabPass@dot.corp.example:853",
        ] {
            let r1 = redact_sensitive_text(fail_closed);
            assert_eq!(
                r1, "***REDACTED_URL***",
                "malformed DoT URL must fail closed: {fail_closed}"
            );
            assert_eq!(redact_sensitive_text(&r1), r1);
        }

        // `anytls://` must not be shadowed or corrupted by `tls://`
        let anytls = redact_sensitive_text("anytls://MyAnyTlsPass@host.example:443");
        assert_eq!(anytls, "anytls://***REDACTED***");
        assert_eq!(redact_sensitive_text(&anytls), anytls);
    }

    #[test]
    fn redact_sensitive_text_blocks_mid_authority_query_scheme_whatwg_ws_backslash_and_proxy_tab() {
        let url_vectors: [(&str, &[&str]); 21] = [
            (
                "https://authuser\t:authsecret99@doh.example/dns-query",
                &["authuser", "authsecret99"],
            ),
            (
                "https://authuser:\tauthsecret88@doh.example/dns-query",
                &["authuser", "authsecret88"],
            ),
            (
                "https://bsuser:8080\t\\bspass99@doh.example/dns-query",
                &["bsuser", "8080", "bspass99"],
            ),
            (
                "https://bsuser:8080\\\tbspass99@doh.example/dns-query",
                &["bsuser", "8080", "bspass99"],
            ),
            (
                "https://\\\tuser:8080\\leadbspass@doh.example/dns-query",
                &["user", "8080", "leadbspass"],
            ),
            (
                "https://\t/miduser:8080\t\\midpass99@doh.example/dns-query",
                &["miduser", "8080", "midpass99"],
            ),
            (
                "https://\tnosuser:8080\t\\nospass99@doh.example/dns-query",
                &["nosuser", "8080", "nospass99"],
            ),
            (
                "https://lfmiduser:8080\n\\lfmidpass99@doh.example/dns-query",
                &["lfmiduser", "8080", "lfmidpass99"],
            ),
            (
                "https://crmiduser:8080\r\\crmidpass99@doh.example/dns-query",
                &["crmiduser", "8080", "crmidpass99"],
            ),
            (
                "https://atboxuser:8080\t@doh.example/dns-query",
                &["atboxuser", "8080"],
            ),
            (
                "https://u\tser:8080\\InnerTabPass@doh.example/dns-query",
                &["InnerTabPass", "8080"],
            ),
            (
                "https://user\r:CrColonPass@doh.example/dns-query",
                &["CrColonPass"],
            ),
            (
                "https://user\n:LfColonPass@doh.example/dns-query",
                &["LfColonPass"],
            ),
            (
                "https://dns.google/dns-query?token=\tTabQuerySecret99",
                &["TabQuerySecret99"],
            ),
            (
                "https://dns.google/dns-query?token\t=TabQueryEqSecret99",
                &["TabQueryEqSecret99"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3\t/TabNextDnsDevice",
                &["a1b2c3", "TabNextDnsDevice"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3/\tTabSlashNextDnsDevice",
                &["a1b2c3", "TabSlashNextDnsDevice"],
            ),
            (
                "ht\ttps://schuser:8080\\schpass@doh.example/x",
                &["schuser", "8080", "schpass"],
            ),
            (
                "https:\t//user:8080\\SchemeTabPass@doh.example/dns-query",
                &["SchemeTabPass", "8080"],
            ),
            (
                "https:/\t/user:8080\\SlashTabPass@doh.example/dns-query",
                &["SlashTabPass", "8080"],
            ),
            (
                r"https:/\ssbuser:8080\ssbpass@doh.example/x",
                &["ssbuser", "8080", "ssbpass"],
            ),
        ];

        for (input, forbidden) in url_vectors {
            let r1 = redact_sensitive_text(input);
            assert_eq!(
                r1, "***REDACTED_URL***",
                "WHATWG ws/backslash URL must fail closed: {input:?}"
            );
            for secret in forbidden {
                assert!(
                    !r1.contains(secret),
                    "secret '{secret}' leaked in '{r1}' for {input:?}"
                );
            }
            assert_eq!(redact_sensitive_text(&r1), r1);
        }

        // Additional backslash-scheme variants (`https:\\`, `http:/\`, `http:\\`, `https:\/`)
        for bs_scheme in [
            r"https:\\dbsuser:8080\dbspass@doh.example/x",
            r"http:/\huser:80\hpass@doh.example/x",
            r"http:\\h2user:80\h2pass@doh.example/x",
            r"https:\/juser:443\jpass@doh.example/x",
        ] {
            let r1 = redact_sensitive_text(bs_scheme);
            assert_eq!(r1, "***REDACTED_URL***", "failed on {bs_scheme}");
            assert_eq!(redact_sensitive_text(&r1), r1);
        }

        // Opaque proxy share links with leading `\t`/`\r`/`\n`
        let ss_tab = redact_sensitive_text("ss://\tYWVzLTI1Ni1nY206U2VjcmV0U3NQYXNz==");
        assert_eq!(ss_tab, "ss://***REDACTED***");
        assert_eq!(redact_sensitive_text(&ss_tab), ss_tab);

        let vmess_tab =
            redact_sensitive_text("vmess://\teyJhZGQiOiIxLjIuMy40IiwiaWQiOiJWbWVzc1NlY3JldCJ9");
        assert_eq!(vmess_tab, "vmess://***REDACTED***");
        assert_eq!(redact_sensitive_text(&vmess_tab), vmess_tab);

        // Benign TSV & multi-line logs stay uncorrupted and strictly idempotent
        for (input, expected) in [
            (
                "url:\thttps://example.com/a\tstatus=200",
                "url:\thttps://example.com/***REDACTED***\tstatus=200",
            ),
            (
                "expected https://\nnext line",
                "expected https://\nnext line",
            ),
            (
                "http://\thttps://example.com/a",
                "http://\thttps://example.com/***REDACTED***",
            ),
            ("https://a.com\tcol2", "https://a.com\tcol2"),
            ("https://a.com\nnext line", "https://a.com\nnext line"),
            (
                "Check https://example.com:\nnext line",
                "Check https://example.com:\nnext line",
            ),
            (
                "https://example.com/a\n# yaml comment",
                "https://example.com/***REDACTED***\n# yaml comment",
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(r1, expected, "unexpected output for {input:?}");
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }
    }

    #[test]
    fn redact_sensitive_text_preserves_uuid_host_placeholder_case_unblocks_uuid_kv_and_scrubs_quoted_auth()
     {
        // Uppercase `***REDACTED***` preserved in URL hostnames and strictly idempotent
        for (input, expected) in [
            (
                "https://12345678-1234-4321-abcd-998877665544.example/secret-path",
                "https://***REDACTED***.example/***REDACTED***",
            ),
            (
                "https://12345678-1234-4321-abcd-998877665544/a",
                "https://***REDACTED***/***REDACTED***",
            ),
            (
                "tls://12345678-1234-4321-abcd-998877665544.example:853/secret-path",
                "tls://***REDACTED***.example:853/***REDACTED***",
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            assert_eq!(r1, expected, "unexpected pass-1 output for {input}");
            assert!(
                !r1.contains("***redacted***"),
                "lowercase placeholder in {r1}"
            );
            assert_eq!(r2, r1, "must be strictly idempotent for {input}");
        }

        // UUID-glued KV secrets scrub cleanly on Pass 1 and remain strictly idempotent
        for (input, expected, secret) in [
            (
                "12345678-1234-4321-abcd-998877665544token=EmptyCfgSecret999",
                "***REDACTED***token=***REDACTED***",
                "EmptyCfgSecret999",
            ),
            (
                "12345678-1234-4321-abcd-998877665544password=SuperPass888",
                "***REDACTED***password=***REDACTED***",
                "SuperPass888",
            ),
            (
                "token=12345678-1234-4321-abcd-998877665544-tail",
                "token=***REDACTED***",
                "tail",
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            assert_eq!(r1, expected, "unexpected pass-1 output for {input}");
            assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            assert_eq!(r2, r1, "must be strictly idempotent for {input}");
        }

        // Quoted and JSON-escaped Authorization Bearer / Basic headers
        for (input, expected, secret) in [
            (
                r#"Authorization: Bearer "QuotedBearerSecret789""#,
                r#"Authorization: Bearer "***REDACTED***""#,
                "QuotedBearerSecret789",
            ),
            (
                "Authorization: Basic 'QuotedBasicSecret654'",
                "Authorization: Basic '***REDACTED***'",
                "QuotedBasicSecret654",
            ),
            (
                "Proxy-Authorization: Bearer `TickBearerSecret321`",
                "Proxy-Authorization: Bearer `***REDACTED***`",
                "TickBearerSecret321",
            ),
            (
                r#"{"h":"Authorization: Bearer \"QuotedJsonBearer99\""}"#,
                r#"{"h":"Authorization: Bearer \"***REDACTED***\""}"#,
                "QuotedJsonBearer99",
            ),
            (
                "Authorization: Bearer \"UnclosedSecret99\nnext line",
                "Authorization: Bearer \"***REDACTED***\nnext line",
                "UnclosedSecret99",
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            assert_eq!(r1, expected, "unexpected quoted auth redaction for {input}");
            assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            assert_eq!(r2, r1, "quoted auth must be idempotent for {input}");
        }
    }

    #[test]
    fn redact_sensitive_text_handles_repeated_unclosed_sub_and_tab_runs_in_linear_time() {
        let sub_no_close = "Sub (".repeat(10_000);
        let sub_with_nl = format!("{}\n", "Sub (".repeat(10_000));
        let tab_no_at = format!("https://a{}", "\tb".repeat(20_000));
        let repeated_scheme_tab = "https://\t".repeat(5_000);

        let started = std::time::Instant::now();
        assert_eq!(redact_sensitive_text(&sub_no_close), sub_no_close);
        assert_eq!(redact_sensitive_text(&sub_with_nl), sub_with_nl);
        let r_tab = redact_sensitive_text(&tab_no_at);
        assert!(r_tab.starts_with("https://a\tb"));
        assert_eq!(redact_sensitive_text(&r_tab), r_tab);
        assert_eq!(
            redact_sensitive_text(&repeated_scheme_tab),
            repeated_scheme_tab
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "50k unclosed Sub ( and tab runs must execute in O(N) time, took {elapsed:?}"
        );
    }

    #[test]
    fn redact_sensitive_text_monotone_horizon_scales_linearly_on_backslash_and_bracket_inputs() {
        let payloads = [
            "https:\\\\a\t".repeat(5_000),
            "https:\\\\\t".repeat(5_000),
            "http:\\\\a\t".repeat(5_000),
            "https:\t\\\\a\t".repeat(5_000),
            "ht\ttps:\\\\a\t".repeat(5_000),
            "https:\\\\[a]\t".repeat(5_000),
            "https:\t\\\\[a]\t".repeat(5_000),
            "https:\t\\\\[@]\t".repeat(5_000),
            "https:\t\\\\[a\t]".repeat(5_000),
            "https:\t\\\\[a\t".repeat(5_000),
            "https://a\\\t".repeat(5_000),
            "https://a\t\\\t".repeat(5_000),
            "https://[a\t]".repeat(5_000),
            "https://[\ta]".repeat(5_000),
            format!("{}@", "https:\\\\[a\ta\tb]a:\\\\".repeat(5_000)),
            format!("{}@", "https:\t\\\\[a\ta\tb]a:\\\\".repeat(5_000)),
            format!("{}@", "https:\\\\[a\ta\tb]https:\\\\x".repeat(5_000)),
            "https://\t[1\t:2]".repeat(5_000),
            "https://\t[\t1\t:2]".repeat(5_000),
            "https://\ta\t/".repeat(5_000),
            "https://\ta\t/x".repeat(5_000),
            "https://a.\t".repeat(5_000),
            format!("{}@", "https://a\\b\tc".repeat(5_000)),
            "token=a\" ".repeat(10_000),
            format!("token=a\"{}", "b".repeat(50_000)),
        ];

        let started = std::time::Instant::now();
        for payload in &payloads {
            let r1 = redact_sensitive_text(payload);
            let r2 = redact_sensitive_text(&r1);
            assert_eq!(r2, r1, "monotone horizon output must be idempotent");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(4),
            "backslash, bracketed, leading-tab & dot-tab WHATWG inputs must scale strictly O(N), took {elapsed:?}"
        );
    }

    #[test]
    fn redact_sensitive_text_wave6_fix_c_ipv6_scheme_patterns_scale_linearly_at_16k() {
        let patterns: [(&str, String); 6] = [
            (
                "bs_ipv6_a_bs_at_16k",
                format!("{}@", "https:\\\\[a\ta\tb]a:\\\\".repeat(16_000)),
            ),
            (
                "tab_bs_ipv6_a_bs_at_16k",
                format!("{}@", "https:\t\\\\[a\ta\tb]a:\\\\".repeat(16_000)),
            ),
            (
                "bs_ipv6_https_bs_at_16k",
                format!("{}@", "https:\\\\[a\ta\tb]https:\\\\x".repeat(16_000)),
            ),
            ("lead_tab_ipv6_16k", "https://\t[1\t:2]".repeat(16_000)),
            ("lead_tab_slash_16k", "https://\ta\t/".repeat(16_000)),
            ("dot_before_tab_16k", "https://a.\t".repeat(16_000)),
        ];

        for (label, payload) in &patterns {
            let started = std::time::Instant::now();
            let r1 = redact_sensitive_text(payload);
            let t1 = started.elapsed();
            let r2 = redact_sensitive_text(&r1);
            assert_eq!(r2, r1, "output must be idempotent for {label}");
            println!("{label}: len={} elapsed={t1:?}", payload.len());
            assert!(
                t1 < std::time::Duration::from_secs(2),
                "{label} (len={}) must scale strictly O(N), took {t1:?}",
                payload.len()
            );
        }
    }

    #[test]
    fn redact_sensitive_text_bridges_leading_mid_host_root_slash_mid_path_query_ws_and_handles_ws_schemes()
     {
        let fail_closed_vectors: [(&str, &[&str]); 21] = [
            (
                "https://\tdns.nextdns.io/SecretProfile99",
                &["SecretProfile99"],
            ),
            (
                "https://\rdns.nextdns.io/SecretProfile99",
                &["SecretProfile99"],
            ),
            (
                "https://\ndns.nextdns.io/SecretProfile99",
                &["SecretProfile99"],
            ),
            (
                "https://\t198.51.100.77/SecretSubToken99",
                &["198.51.100.77", "SecretSubToken99"],
            ),
            (
                "tls://\tdns.nextdns.io/DotLeadTabSecret99",
                &["DotLeadTabSecret99"],
            ),
            (
                "ht\ttps://\tdns.nextdns.io/SchLeadTabSecret99",
                &["SchLeadTabSecret99"],
            ),
            (
                "https:\t//\tdns.nextdns.io/ColLeadTabSecret99",
                &["ColLeadTabSecret99"],
            ),
            (
                "https:/\\\tdns.nextdns.io/BsLeadTabSecret99",
                &["BsLeadTabSecret99"],
            ),
            (
                "https:\\\\\tdns.nextdns.io/DbsLeadTabSecret99",
                &["DbsLeadTabSecret99"],
            ),
            (
                "https://doh\t.example/a1b2c3/HostMidTabSecret",
                &["a1b2c3", "HostMidTabSecret"],
            ),
            (
                "https://dns.next\tdns.io/MidHostTabSecret99",
                &["MidHostTabSecret99"],
            ),
            (
                "https://198.51\t.100.77/MidIpTabSecret99",
                &["100.77", "MidIpTabSecret99"],
            ),
            (
                "tls://dot\t.corp.example:853/DotHostTabSecret",
                &["DotHostTabSecret"],
            ),
            (
                "https://dns.next\tdns.io/dns-query?token=MidHostQuerySecret99",
                &["MidHostQuerySecret99"],
            ),
            (
                "https://dns.nextdns.io/\tRootSlashTabSecret99",
                &["RootSlashTabSecret99"],
            ),
            (
                "https://dns.nextdns.io/\rRootSlashCrSecret99",
                &["RootSlashCrSecret99"],
            ),
            (
                "https://sub.example.com/\tapi/v1/RootSubSecret99",
                &["RootSubSecret99"],
            ),
            (
                "tls://dot.corp.example:853/\tDotRootTabSecret",
                &["DotRootTabSecret"],
            ),
            (
                "https://dns.nextdns.io/a1\tb2c3/MidSegTabSecret",
                &["b2c3", "MidSegTabSecret"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3/\nLfDeviceSecret99",
                &["a1b2c3", "LfDeviceSecret99"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3/\tdev=EqAfterSlashSecret",
                &["a1b2c3", "EqAfterSlashSecret"],
            ),
        ];
        for (input, forbidden) in fail_closed_vectors {
            let r1 = redact_sensitive_text(input);
            assert_eq!(
                r1, "***REDACTED_URL***",
                "WHATWG tab/CR/LF URL must fail closed: {input:?}"
            );
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(redact_sensitive_text(&r1), r1);
        }

        let query_mid_tab =
            redact_sensitive_text("https://doh.example/dns-query?token=abc\tQueryMidTabSecret");
        assert_eq!(query_mid_tab, "***REDACTED_URL***");
        assert!(!query_mid_tab.contains("QueryMidTabSecret"));
        assert_eq!(redact_sensitive_text(&query_mid_tab), query_mid_tab);

        // `ws://` and `wss://` (plain, non-loopback IP, tab-split, and backslash forms)
        for (input, expected, forbidden) in [
            (
                "ws://wsuser:WsPlainPass99@ws.corp.example:80/WsPlainPath88",
                "ws://ws.corp.example/***REDACTED***",
                &["wsuser", "WsPlainPass99", "WsPlainPath88"][..],
            ),
            (
                "wss://wssuser:WssPlainPass99@ws.corp.example:443/WssPlainPath88",
                "wss://ws.corp.example/***REDACTED***",
                &["wssuser", "WssPlainPass99", "WssPlainPath88"][..],
            ),
            (
                "wss://198.51.100.77:8443/secret",
                "wss://***REDACTED***",
                &["198.51.100.77", "secret"][..],
            ),
            (
                "ws\ts://wsuser:WssTabPass99@ws.corp.example:443/WssTabPath88",
                "***REDACTED_URL***",
                &["wsuser", "WssTabPass99", "WssTabPath88"][..],
            ),
            (
                r"wss:\\wsuser:443\WssBsPass99@ws.corp.example/path",
                "***REDACTED_URL***",
                &["wsuser", "WssBsPass99", "path"][..],
            ),
            (
                r"ws:/\wsuser:80\WsBsPass99@ws.corp.example/path",
                "***REDACTED_URL***",
                &["wsuser", "WsBsPass99", "path"][..],
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            assert_eq!(r1, expected, "unexpected ws/wss redaction for {input:?}");
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(redact_sensitive_text(&r1), r1);
        }

        // Benign TSV and multi-line logs stay intact and strictly idempotent (f(x)==f(f(x))==f(f(f(x))))
        for (input, expected) in [
            (
                "expected https://\nnext line",
                "expected https://\nnext line",
            ),
            (
                "http://\thttps://example.com/a",
                "http://\thttps://example.com/***REDACTED***",
            ),
            ("https://a.com\tcol2", "https://a.com\tcol2"),
            ("http://example.com\t200\tOK", "http://example.com\t200\tOK"),
            ("ws://a.com\tcol2", "ws://a.com\tcol2"),
            ("wss://a.com\tcol2", "wss://a.com\tcol2"),
            ("https://a.com\nnext line", "https://a.com\nnext line"),
            (
                "url:\thttps://example.com/a\tstatus=200",
                "url:\thttps://example.com/***REDACTED***\tstatus=200",
            ),
            (
                "https://example.com/\nnext line",
                "https://example.com/\nnext line",
            ),
            (
                "https://example.com/a\n# yaml comment",
                "https://example.com/***REDACTED***\n# yaml comment",
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(r1, expected, "unexpected benign output for {input:?}");
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }

        // Canonical exported `ENDPOINT_URL_SCHEMES` covers HTTP/WS/DNS/proxy schemes
        for expected_scheme in [
            "http://",
            "https://",
            "ws://",
            "wss://",
            "tls://",
            "quic://",
            "h3://",
            "doq://",
            "tcp://",
            "udp://",
            "sdns://",
            "socks5://",
            "socks5h://",
            "socks4://",
            "socks://",
            "ss://",
            "ssr://",
            "vmess://",
            "vless://",
            "trojan://",
            "hysteria://",
            "hysteria2://",
            "hy2://",
            "tuic://",
            "anytls://",
            "wireguard://",
            "wg://",
            "ssh://",
            "juicity://",
            "mieru://",
            "snell://",
        ] {
            assert!(
                ENDPOINT_URL_SCHEMES.contains(&expected_scheme),
                "ENDPOINT_URL_SCHEMES missing {expected_scheme}"
            );
            assert!(has_endpoint_url_scheme_prefix(&format!(
                "{expected_scheme}example"
            )));
            assert!(contains_endpoint_url_scheme(&format!(
                "err:{expected_scheme}example"
            )));
        }
    }

    #[test]
    fn redact_sensitive_text_scrubs_quoted_and_json_escaped_kv_and_json_object_authorization() {
        let cases: [(&str, &str, &[&str]); 16] = [
            (
                r#"level=warn msg="auth fail" password="QuotedKvPassword999""#,
                r#"level=warn msg="auth fail" password="***REDACTED***""#,
                &["QuotedKvPassword999"],
            ),
            (
                "level=warn token='SingleKvToken888'",
                "level=warn token='***REDACTED***'",
                &["SingleKvToken888"],
            ),
            (
                "level=warn api_key=`BacktickKvApiKey777`",
                "level=warn api_key=`***REDACTED***`",
                &["BacktickKvApiKey777"],
            ),
            (
                r#"{"msg":"fail secret=\"JsonEscapedKvSecret666\""}"#,
                r#"{"msg":"fail secret=\"***REDACTED***\""}"#,
                &["JsonEscapedKvSecret666"],
            ),
            (
                r#"private_key="QuotedPrivKey555" pbk="QuotedPbk444""#,
                r#"private_key="***REDACTED***" pbk="***REDACTED***""#,
                &["QuotedPrivKey555", "QuotedPbk444"],
            ),
            (
                r#"secret=\"a\\\"InnerEscSecret555\""#,
                r#"secret=\"***REDACTED***\""#,
                &["InnerEscSecret555"],
            ),
            (
                r#"password="my\"InnerQuoteSecret444""#,
                r#"password="***REDACTED***""#,
                &["InnerQuoteSecret444"],
            ),
            (
                r#"password="" secret=\"\""#,
                r#"password="" secret=\"\""#,
                &[],
            ),
            (
                "password=\"UnclosedKvSecret333\nnext line",
                "password=\"***REDACTED***\nnext line",
                &["UnclosedKvSecret333"],
            ),
            (
                r#"{"Authorization": "Bearer JsonObjBearerSecret999"}"#,
                r#"{"Authorization": "Bearer ***REDACTED***"}"#,
                &["JsonObjBearerSecret999"],
            ),
            (
                r#"{"Authorization": "Basic JsonObjBasicSecret888"}"#,
                r#"{"Authorization": "Basic ***REDACTED***"}"#,
                &["JsonObjBasicSecret888"],
            ),
            (
                r#"{"Proxy-Authorization": "Bearer ProxyJsonBearer777"}"#,
                r#"{"Proxy-Authorization": "Bearer ***REDACTED***"}"#,
                &["ProxyJsonBearer777"],
            ),
            (
                r#"{\"Authorization\": \"Bearer EscObjBearer666\"}"#,
                r#"{\"Authorization\": \"Bearer ***REDACTED***\"}"#,
                &["EscObjBearer666"],
            ),
            (
                "{'Authorization': 'Bearer SingleObjBearer555'}",
                "{'Authorization': 'Bearer ***REDACTED***'}",
                &["SingleObjBearer555"],
            ),
            (
                r#"Authorization: Bearer \"part1\\\"EscapedInnerBearer777\""#,
                r#"Authorization: Bearer \"***REDACTED***\""#,
                &["part1", "EscapedInnerBearer777"],
            ),
            (
                r#"{"Authorization": "Bearer "}"#,
                r#"{"Authorization": "Bearer "}"#,
                &[],
            ),
        ];

        for (input, expected, forbidden) in cases {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            assert_eq!(r1, expected, "unexpected redaction for {input:?}");
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(r2, r1, "redaction must be idempotent for {input:?}");
        }

        // JSON object Authorization & JSON-escaped KV stay valid JSON after redaction
        for valid_json in [
            r#"{"Authorization": "Bearer JsonObjBearerSecret999"}"#,
            r#"{"Authorization": "Basic JsonObjBasicSecret888"}"#,
            r#"{"msg":"fail secret=\"JsonEscapedKvSecret666\""}"#,
            r#"{"msg":"secret=\"a\\\"b\""}"#,
        ] {
            let redacted = redact_sensitive_text(valid_json);
            serde_json::from_str::<serde_json::Value>(&redacted)
                .expect("redacted JSON payload must remain syntactically valid JSON");
        }
    }

    #[test]
    fn redact_sensitive_text_bridges_whatwg_backslash_ws_ipv6_bracket_tabs_and_leading_tab_bare_ips()
     {
        let hostile_vectors: [(&str, &[&str]); 23] = [
            // WHATWG `\`+`\t`/`\r`/`\n` & `\t\`+`\t` special-scheme path/credential vectors
            ("https://dns.nextdns.io\\\tSecretPath99", &["SecretPath99"]),
            ("https://dns.nextdns.io\\\rSecretPath99", &["SecretPath99"]),
            (
                "https://dns.nextdns.io\t\\\tSecretPath99",
                &["SecretPath99"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3\\\tSecretPath99",
                &["a1b2c3", "SecretPath99"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3\\\nLfBsPathSecret99",
                &["a1b2c3", "LfBsPathSecret99"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3\t\\\tSecretPath99",
                &["a1b2c3", "SecretPath99"],
            ),
            (
                "https://user\t\\\tPass99@host.example/p",
                &["user", "Pass99", "host.example"],
            ),
            (
                "wss://ws.corp.example\\\tWsSecretPath99",
                &["WsSecretPath99"],
            ),
            // WHATWG IPv6 `[...]` bracket-tab & bracketed-username vectors
            (
                "https://[2606:4700:4700::1111\t]/SecretV6Trail99",
                &["2606:4700", "SecretV6Trail99"],
            ),
            ("https://[2606:4700:4700::1111\t]", &["2606:4700", "1111"]),
            (
                "https://[\t2606:4700:4700::1111]/SecretV6Lead99",
                &["2606:4700", "SecretV6Lead99"],
            ),
            (
                "https://[2606:47\t00::1111]/SecretV6Mid99",
                &["2606:47", "00::1111", "SecretV6Mid99"],
            ),
            (
                "https://[2606:47\t00::\t1111]/SecretV6MultiTab99",
                &["2606:47", "1111", "SecretV6MultiTab99"],
            ),
            (
                "https://[2606:4700:\tabcd::1111]/SecretV6Hex99",
                &["2606:4700", "abcd::1111", "SecretV6Hex99"],
            ),
            ("https://[::1\t]:8443/SecretV6Loop99", &["SecretV6Loop99"]),
            (
                "tls://[2606:4700:4700::1111\t]:853/SecretTlsV6Trail99",
                &["2606:4700", "SecretTlsV6Trail99"],
            ),
            (
                "tls://[\t2606:4700:4700::1111]:853/SecretTlsV6Lead99",
                &["2606:4700", "SecretTlsV6Lead99"],
            ),
            (
                "https://[a\t]user:SecretPass99@host.example/p",
                &["SecretPass99", "host.example"],
            ),
            (
                "https:\t\\\\[a\t]user:SecretPass99@host.example/p",
                &["SecretPass99", "host.example"],
            ),
            // Leading-tab bare non-loopback IP / IP:port / IPv6 literals
            ("https://\t198.51.100.77", &["198.51.100.77"]),
            ("https://\t198.51.100.77:8443", &["198.51.100.77", "8443"]),
            (
                "https://\t[2606:4700:4700::1111]:8443",
                &["2606:4700", "8443"],
            ),
            (
                "https://\t[\t2606:4700:4700::1111]/SecretV6DoubleLead99",
                &["2606:4700", "SecretV6DoubleLead99"],
            ),
        ];

        for (input, forbidden) in hostile_vectors {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(
                r1, "***REDACTED_URL***",
                "WHATWG backslash/IPv6/bare-IP vector must fail closed: {input:?}"
            );
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }

        // Benign JSON, TSV KV, trailing-backslash, and multi-line logs stay intact & idempotent
        for (input, expected) in [
            (r#"["https://example.com"]"#, r#"["https://example.com"]"#),
            (r#"{"url":"https://a.com\"}"#, r#"{"url":"https://a.com\"}"#),
            ("https://a.com\\\nnext line", "https://a.com\\\nnext line"),
            ("https://a.com/\\\nnext line", "https://a.com/\\\nnext line"),
            ("https://a.com\\\tstatus=200", "https://a.com\\\tstatus=200"),
            (
                "https://a.com\t\\\tstatus=200",
                "https://a.com\t\\\tstatus=200",
            ),
            (
                "expected https://\n[10:00:00] ok",
                "expected https://\n[10:00:00] ok",
            ),
            ("https://a.com\tcol2", "https://a.com\tcol2"),
            ("http://example.com\t200\tOK", "http://example.com\t200\tOK"),
            ("ws://a.com\tcol2", "ws://a.com\tcol2"),
            ("wss://a.com\tcol2", "wss://a.com\tcol2"),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(r1, expected, "benign input must stay intact: {input:?}");
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }
    }

    #[test]
    fn redact_sensitive_text_verbatim_noop_dot_segment_tsv_and_unified_whatwg_rules() {
        // 1. Verbatim No-Op Invariant on benign URLs (no trailing `/` injection, no default port
        //    stripping, no host/scheme case rewriting, strict f(x)==f(f(x))==f(f(f(x))))
        for benign in [
            "https://a.com",
            "https://a.com/",
            "https://a.com:443",
            "http://example.com:80",
            "HTTPS://Example.COM",
            "HTTPS://Example.COM:443",
            "ws://a.com:80",
            "wss://a.com:443",
            "http://127.0.0.1:8080",
            "https://[::1]:8443",
            "Check https://example.com:\nnext line",
            "https://a.com\tcol2",
            "http://example.com\t200\tOK",
            "ws://a.com\tcol2",
            "wss://a.com\tcol2",
            "tls://1.1.1.1:853",
            "tls://dot.example.com:853/",
        ] {
            let r1 = redact_sensitive_text(benign);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(r1, benign, "benign URL must remain verbatim: {benign:?}");
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {benign:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {benign:?}");
        }

        // 2. Dot-segment TSV URLs redact directly on Pass 1 with ZERO secret leakage & strict idempotency
        for (input, expected, forbidden) in [
            (
                "https://a.com/.\tcol2",
                "https://a.com/***REDACTED***\tcol2",
                &[][..],
            ),
            (
                "https://a.com/./\tcol2",
                "***REDACTED_URL***",
                &["col2"][..],
            ),
            (
                "https://a.com/./ status=200",
                "https://a.com/***REDACTED*** status=200",
                &[][..],
            ),
            (
                "https://a.com/a/..\tcol2",
                "https://a.com/***REDACTED***\tcol2",
                &[][..],
            ),
            (
                "https://a.com/SecretPath99/..\tcol2",
                "https://a.com/***REDACTED***\tcol2",
                &["SecretPath99"][..],
            ),
            (
                "https://a.com/%2e\tcol2",
                "https://a.com/***REDACTED***\tcol2",
                &[][..],
            ),
            (
                "https://a.com/%2E\tcol2",
                "https://a.com/***REDACTED***\tcol2",
                &[][..],
            ),
            (
                "https://a.com\\SecretPath99\\..\tcol2",
                "https://a.com/***REDACTED***\tcol2",
                &["SecretPath99"][..],
            ),
            (
                "tls://dot.example.com:853/.\tcol2",
                "tls://dot.example.com:853/***REDACTED***\tcol2",
                &[][..],
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(r1, expected, "dot-segment TSV failed on {input:?}");
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }

        // 3. Wave 6 Reviewer 2 (N_C1..N_C9), Challenger 1 (D3 #1..#7), and Challenger 2 (D2 #1..#8)
        //    unified WHATWG special-scheme backslash, multi-LF IPv6, leading-tab multi-token/IPv6/IPv4,
        //    and dot-before-tab vectors
        let hostile_vectors: [(&str, &[&str]); 24] = [
            // R2 N_C1..N_C9
            (
                "https://dns.nextdns.io/a1\tb2c3\\MidPathBsSecret99",
                &["b2c3", "MidPathBsSecret99"],
            ),
            (
                "https://dns.next\tdns.io\\MidHostBsSecret99",
                &["MidHostBsSecret99"],
            ),
            (
                "https://\tdns.nextdns.io\\LeadTabBsSecret99",
                &["LeadTabBsSecret99"],
            ),
            (
                "https://\t[2606\t:4700:4700::1111]/SecretV6Colon99",
                &["2606", "4700", "SecretV6Colon99"],
            ),
            (
                "https://\t[\t2606\t:4700:4700::1111]/SecretV6ColonLead99",
                &["2606", "4700", "SecretV6ColonLead99"],
            ),
            ("https://\t198.51\t.100.77", &["198.51", "100.77"]),
            (
                "https://dns.nextdns.io/a1b2c3\\\tdev=EqAfterBsSecret99",
                &["a1b2c3", "EqAfterBsSecret99"],
            ),
            (
                "https://dns.nextdns.io\\a1b2c3\\\nAfterBsSegLfSecret99",
                &["a1b2c3", "AfterBsSegLfSecret99"],
            ),
            // C1 D3 #1..#7
            (
                "https://[2606:\nabcd:\n4700::1111]/SecretV6MultiNlHex99",
                &["2606", "abcd", "4700", "SecretV6MultiNlHex99"],
            ),
            (
                "https://[2606:47\n00:47\n00::1111]/SecretV6MultiNlMid99",
                &["2606", "00:47", "SecretV6MultiNlMid99"],
            ),
            (
                "https://[2606:\n4700\n:1111]/SecretV6MultiNlPureHex99",
                &["2606", "4700", "1111", "SecretV6MultiNlPureHex99"],
            ),
            (
                "https://[2606:4700:\n47\n00::1111]/SecretV6MultiNlSplitHextet99",
                &["2606", "4700", "SecretV6MultiNlSplitHextet99"],
            ),
            ("https://\t198.51.\t100.77", &["198.51", "100.77"]),
            (
                "https://\t198.51.\t100.77/SecretIpMid99",
                &["198.51", "100.77", "SecretIpMid99"],
            ),
            (
                "https://\tdns.\tnextdns.io/SecretDomMid99",
                &["SecretDomMid99"],
            ),
            (
                "https://198.\t51.\t100.77/SecretIp2Tab99",
                &["51.", "100.77", "SecretIp2Tab99"],
            ),
            // C2 D2 #1..#8 + bare port & trailing-backslash mid-path
            (
                "https://\tdns.nextdns.io\t/SecretLeadTabDom99",
                &["SecretLeadTabDom99"],
            ),
            (
                "https://\t198.51.100.77:\t8443/SecretLeadTabIpPort99",
                &["198.51.100.77", "8443", "SecretLeadTabIpPort99"],
            ),
            (
                "https://\t[2606:4700:4700::1111]:\t8443/SecretLeadTabV6Port99",
                &["2606:4700", "8443", "SecretLeadTabV6Port99"],
            ),
            (
                "tls://\t[2606\t:4700:4700::1111]:853/TlsLeadTabV6Sec99",
                &["2606", "4700", "TlsLeadTabV6Sec99"],
            ),
            (
                "wss://\tws.corp.example\t/WsLeadTabSec99",
                &["WsLeadTabSec99"],
            ),
            ("https://\t198.51.100.77:\t8443", &["198.51.100.77", "8443"]),
            (
                "https://\t[2606:4700:4700::1111]:\t8443",
                &["2606:4700", "8443"],
            ),
            (
                "https://dns.nextdns.io/a1\tb2c3\\\tSecretMidPathTrailBs99",
                &["b2c3", "SecretMidPathTrailBs99"],
            ),
        ];

        for (input, forbidden) in hostile_vectors {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(
                r1, "***REDACTED_URL***",
                "unified WHATWG vector must fail closed: {input:?}"
            );
            for secret in forbidden {
                assert!(!r1.contains(secret), "leaked '{secret}' in '{r1}'");
            }
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }

        // 4. Benign preservation controls for leading-tab, IPv6 brackets, backslash TSV, and inline quotes
        for (input, expected) in [
            ("https://\tcol2", "https://\tcol2"),
            ("https://\tcol1\tcol2", "https://\tcol1\tcol2"),
            ("https://\nnext line", "https://\nnext line"),
            (
                "expected https://\n[10:00:00] ok",
                "expected https://\n[10:00:00] ok",
            ),
            ("https://\t[10:00:00]", "https://\t[10:00:00]"),
            (
                "expected https://[\nnormal prose",
                "expected ***REDACTED_URL***\nnormal prose",
            ),
            (
                "expected https://[\nface\nnormal prose",
                "expected ***REDACTED_URL***\nface\nnormal prose",
            ),
            (r#"["https://example.com"]"#, r#"["https://example.com"]"#),
            (r#"{"url":"https://a.com\"}"#, r#"{"url":"https://a.com\"}"#),
            ("https://a.com\\\nnext line", "https://a.com\\\nnext line"),
            ("https://a.com\\\tstatus=200", "https://a.com\\\tstatus=200"),
            (
                "https://a.com\t\\\tstatus=200",
                "https://a.com\t\\\tstatus=200",
            ),
            (
                "https://a.com\t\\\\\tstatus=200",
                "https://a.com\t\\\\\tstatus=200",
            ),
            (
                "https://dns.nextdns.io/a1b2c3\\\nstatus=200",
                "https://dns.nextdns.io/***REDACTED***\\\nstatus=200",
            ),
            (
                r#"DOMAIN-KEYWORD,token=foo_xkey="a"-AdvQuotedSplitTail55,DIRECT"#,
                "DOMAIN-KEYWORD,token=***REDACTED***,DIRECT",
            ),
            (
                r#"msg="token=secret_val" other="foo""#,
                r#"msg="token=***REDACTED***" other="foo""#,
            ),
            (
                r#"{"msg":"token=secret_val"}"#,
                r#"{"msg":"token=***REDACTED***"}"#,
            ),
            (
                "https://a.com/\thttps://\tc/secret",
                "https://a.com/\t***REDACTED_URL***",
            ),
        ] {
            let r1 = redact_sensitive_text(input);
            let r2 = redact_sensitive_text(&r1);
            let r3 = redact_sensitive_text(&r2);
            assert_eq!(r1, expected, "unexpected output for {input:?}");
            assert_eq!(r2, r1, "f(f(x)) != f(x) for {input:?}");
            assert_eq!(r3, r1, "f(f(f(x))) != f(x) for {input:?}");
        }
    }
}
