use std::{collections::HashMap, net::IpAddr, path::Path};

use ipnet::IpNet;

use crate::error::{ProxyError, Result};

const MMDB_METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const DATA_SECTION_SEPARATOR_SIZE: usize = 16;
const MAX_METADATA_SEARCH_BYTES: usize = 128 * 1024;
const MAX_DECODE_DEPTH: usize = 16;

/// Pure-Rust MaxMind DB (`.mmdb`) v2.0 binary format reader supporting 24-bit, 28-bit, and 32-bit
/// search-tree records, IPv4-in-IPv6 (`::ffff:0:0/96`) fast-path prefix caching, and pointer-compressed
/// GeoLite2-Country / GeoIP2-Country / Country.mmdb data sections.
#[derive(Clone, Debug)]
pub struct MmdbReader {
    raw: Vec<u8>,
    node_count: usize,
    record_size_bits: u16,
    node_byte_size: usize,
    ip_version: u16,
    data_section_start: usize,
    ipv4_start_node: usize,
}

#[derive(Clone, Debug)]
enum MmdbValue {
    Str(String),
    Uint(u64),
    Map(HashMap<String, MmdbValue>),
    Array(Vec<MmdbValue>),
    Other,
}

impl MmdbReader {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| {
            ProxyError::Config(format!(
                "failed reading MaxMind GeoIP database '{}': {e}",
                path.as_ref().display()
            ))
        })?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(raw: Vec<u8>) -> Result<Self> {
        let search_start = raw.len().saturating_sub(MAX_METADATA_SEARCH_BYTES);
        let tail = &raw[search_start..];
        let rel_pos = tail
            .windows(MMDB_METADATA_MARKER.len())
            .rposition(|w| w == MMDB_METADATA_MARKER)
            .ok_or_else(|| {
                ProxyError::Config("invalid .mmdb file: MaxMind metadata marker not found".into())
            })?;
        let meta_start = search_start + rel_pos + MMDB_METADATA_MARKER.len();

        let (meta_val, _) = decode_value(&raw, meta_start, meta_start, 0)?;
        let MmdbValue::Map(meta_map) = meta_val else {
            return Err(ProxyError::Config(
                "invalid .mmdb metadata: expected map".into(),
            ));
        };

        let node_count = meta_map
            .get("node_count")
            .and_then(MmdbValue::as_u64)
            .ok_or_else(|| ProxyError::Config("missing node_count in .mmdb metadata".into()))?
            as usize;
        let record_size_bits = meta_map
            .get("record_size")
            .and_then(MmdbValue::as_u64)
            .ok_or_else(|| ProxyError::Config("missing record_size in .mmdb metadata".into()))?
            as u16;
        let ip_version = meta_map
            .get("ip_version")
            .and_then(MmdbValue::as_u64)
            .unwrap_or(6) as u16;

        if !matches!(record_size_bits, 24 | 28 | 32) {
            return Err(ProxyError::Config(format!(
                "unsupported .mmdb record_size {record_size_bits} (expected 24, 28, or 32)"
            )));
        }
        if !matches!(ip_version, 4 | 6) {
            return Err(ProxyError::Config(format!(
                "unsupported .mmdb ip_version {ip_version}"
            )));
        }

        let node_byte_size = (record_size_bits as usize * 2) / 8;
        let tree_size = node_count
            .checked_mul(node_byte_size)
            .ok_or_else(|| ProxyError::Config(".mmdb tree size overflow".into()))?;
        let data_section_start = tree_size + DATA_SECTION_SEPARATOR_SIZE;
        if data_section_start > meta_start {
            return Err(ProxyError::Config(
                "corrupt .mmdb file: tree overlaps metadata section".into(),
            ));
        }

        let mut reader = Self {
            raw,
            node_count,
            record_size_bits,
            node_byte_size,
            ip_version,
            data_section_start,
            ipv4_start_node: 0,
        };

        if ip_version == 6 {
            // Pre-walk the 96 zero bits (::0:0/96) or IPv4-mapped prefix used by MaxMind v6 trees
            let mut node = 0usize;
            for _ in 0..96 {
                if node >= node_count {
                    break;
                }
                node = reader.read_record(node, 0)?;
            }
            if node < node_count {
                reader.ipv4_start_node = node;
            }
        }

        Ok(reader)
    }

    /// Look up the uppercase ISO-3166 country code (e.g. `"CN"`, `"US"`, `"JP"`) for `ip`.
    pub fn lookup_country_code(&self, ip: IpAddr) -> Option<String> {
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };

        let record = match (self.ip_version, ip) {
            (_, IpAddr::V4(v4)) => {
                let start = if self.ip_version == 6 {
                    self.ipv4_start_node
                } else {
                    0
                };
                self.traverse_bits(start, &v4.octets(), 32).ok()?
            }
            (6, IpAddr::V6(v6)) => self.traverse_bits(0, &v6.octets(), 128).ok()?,
            (4, IpAddr::V6(_)) => return None,
            _ => return None,
        };

        if record <= self.node_count {
            return None;
        }
        let data_offset = self
            .data_section_start
            .checked_add(record - self.node_count - DATA_SECTION_SEPARATOR_SIZE)?;
        if data_offset >= self.raw.len() {
            return None;
        }

        let (val, _) = decode_value(&self.raw, self.data_section_start, data_offset, 0).ok()?;
        extract_iso_code(&val)
    }

    fn traverse_bits(&self, mut node: usize, bytes: &[u8], bit_count: usize) -> Result<usize> {
        for bit_idx in 0..bit_count {
            if node >= self.node_count {
                return Ok(node);
            }
            let byte = bytes[bit_idx >> 3];
            let bit = usize::from((byte >> (7 - (bit_idx & 7))) & 1);
            node = self.read_record(node, bit)?;
        }
        Ok(node)
    }

    fn read_record(&self, node: usize, bit: usize) -> Result<usize> {
        let base = node * self.node_byte_size;
        if base + self.node_byte_size > self.raw.len() {
            return Err(ProxyError::Config(
                "corrupt .mmdb: node read out of bounds".into(),
            ));
        }
        let b = &self.raw[base..base + self.node_byte_size];
        let rec = match (self.record_size_bits, bit) {
            (24, 0) => ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize),
            (24, _) => ((b[3] as usize) << 16) | ((b[4] as usize) << 8) | (b[5] as usize),
            (28, 0) => {
                (((b[3] >> 4) as usize) << 24)
                    | ((b[0] as usize) << 16)
                    | ((b[1] as usize) << 8)
                    | (b[2] as usize)
            }
            (28, _) => {
                (((b[3] & 0x0F) as usize) << 24)
                    | ((b[4] as usize) << 16)
                    | ((b[5] as usize) << 8)
                    | (b[6] as usize)
            }
            (32, 0) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
            (32, _) => u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as usize,
            _ => 0,
        };
        Ok(rec)
    }
}

impl MmdbValue {
    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

fn extract_iso_code(val: &MmdbValue) -> Option<String> {
    match val {
        MmdbValue::Str(s) if !s.is_empty() => Some(s.to_ascii_uppercase()),
        MmdbValue::Map(m) => {
            for key in ["country", "registered_country", "represented_country"] {
                if let Some(MmdbValue::Map(sub)) = m.get(key)
                    && let Some(code) = sub.get("iso_code").and_then(MmdbValue::as_str)
                    && !code.is_empty()
                {
                    return Some(code.to_ascii_uppercase());
                }
            }
            for flat_key in ["country_code", "iso_code"] {
                if let Some(code) = m.get(flat_key).and_then(MmdbValue::as_str)
                    && !code.is_empty()
                {
                    return Some(code.to_ascii_uppercase());
                }
            }
            None
        }
        MmdbValue::Array(items) => items.iter().find_map(extract_iso_code),
        _ => None,
    }
}

fn decode_value(
    buf: &[u8],
    base_offset: usize,
    mut pos: usize,
    depth: usize,
) -> Result<(MmdbValue, usize)> {
    if depth > MAX_DECODE_DEPTH {
        return Err(ProxyError::Config(
            ".mmdb data pointer/nesting exceeded maximum depth".into(),
        ));
    }
    if pos >= buf.len() {
        return Err(ProxyError::Config(
            "unexpected EOF in .mmdb data section".into(),
        ));
    }

    let ctrl = buf[pos];
    pos += 1;
    let mut dtype = (ctrl >> 5) as u16;
    if dtype == 0 {
        if pos >= buf.len() {
            return Err(ProxyError::Config("truncated .mmdb extended type".into()));
        }
        dtype = u16::from(buf[pos]) + 7;
        pos += 1;
    }

    // Type 1: Pointer
    if dtype == 1 {
        let ptr_size = ((ctrl >> 3) & 0x03) as usize;
        let low_bits = (ctrl & 0x07) as usize;
        if pos + ptr_size + 1 > buf.len() {
            return Err(ProxyError::Config("truncated .mmdb pointer".into()));
        }
        let ptr_offset = match ptr_size {
            0 => (low_bits << 8) | (buf[pos] as usize),
            1 => 2048 + ((low_bits << 16) | ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize)),
            2 => {
                526_336
                    + ((low_bits << 24)
                        | ((buf[pos] as usize) << 16)
                        | ((buf[pos + 1] as usize) << 8)
                        | (buf[pos + 2] as usize))
            }
            _ => u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize,
        };
        let next_pos = pos + ptr_size + 1;
        let target = base_offset
            .checked_add(ptr_offset)
            .ok_or_else(|| ProxyError::Config(".mmdb pointer arithmetic overflow".into()))?;
        let (pointed, _) = decode_value(buf, base_offset, target, depth + 1)?;
        return Ok((pointed, next_pos));
    }

    let size_field = (ctrl & 0x1F) as usize;
    let payload_size = match size_field {
        0..=28 => size_field,
        29 => {
            if pos >= buf.len() {
                return Err(ProxyError::Config("truncated .mmdb size(29)".into()));
            }
            let v = 29 + (buf[pos] as usize);
            pos += 1;
            v
        }
        30 => {
            if pos + 2 > buf.len() {
                return Err(ProxyError::Config("truncated .mmdb size(30)".into()));
            }
            let v = 285 + (u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize);
            pos += 2;
            v
        }
        _ => {
            if pos + 3 > buf.len() {
                return Err(ProxyError::Config("truncated .mmdb size(31)".into()));
            }
            let v = 65_821
                + (((buf[pos] as usize) << 16)
                    | ((buf[pos + 1] as usize) << 8)
                    | (buf[pos + 2] as usize));
            pos += 3;
            v
        }
    };

    match dtype {
        // UTF-8 String
        2 => {
            if pos + payload_size > buf.len() {
                return Err(ProxyError::Config("truncated .mmdb UTF-8 string".into()));
            }
            let s = String::from_utf8_lossy(&buf[pos..pos + payload_size]).to_string();
            Ok((MmdbValue::Str(s), pos + payload_size))
        }
        // Double (8 bytes) / Float (4 bytes)
        3 => Ok((MmdbValue::Other, pos + 8)),
        15 => Ok((MmdbValue::Other, pos + 4)),
        // Bytes (4) / uint128 (10)
        4 | 10 => {
            if pos + payload_size > buf.len() {
                return Err(ProxyError::Config("truncated .mmdb byte slice".into()));
            }
            Ok((MmdbValue::Other, pos + payload_size))
        }
        // Unsigned integers: uint16 (5), uint32 (6), uint64 (9)
        5 | 6 | 9 => {
            if payload_size > 8 || pos + payload_size > buf.len() {
                return Err(ProxyError::Config("invalid .mmdb uint".into()));
            }
            let mut acc = 0u64;
            for &b in &buf[pos..pos + payload_size] {
                acc = (acc << 8) | u64::from(b);
            }
            Ok((MmdbValue::Uint(acc), pos + payload_size))
        }
        // int32 (8)
        8 => {
            if pos + payload_size > buf.len() {
                return Err(ProxyError::Config("invalid .mmdb int32".into()));
            }
            Ok((MmdbValue::Other, pos + payload_size))
        }
        // Map (7)
        7 => {
            let mut map = HashMap::with_capacity(payload_size.min(32));
            let mut cur = pos;
            for _ in 0..payload_size {
                let (k_val, next_k) = decode_value(buf, base_offset, cur, depth + 1)?;
                let (v_val, next_v) = decode_value(buf, base_offset, next_k, depth + 1)?;
                if let MmdbValue::Str(k) = k_val {
                    map.insert(k, v_val);
                }
                cur = next_v;
            }
            Ok((MmdbValue::Map(map), cur))
        }
        // Array (11)
        11 => {
            let mut arr = Vec::with_capacity(payload_size.min(32));
            let mut cur = pos;
            for _ in 0..payload_size {
                let (elem, next_c) = decode_value(buf, base_offset, cur, depth + 1)?;
                arr.push(elem);
                cur = next_c;
            }
            Ok((MmdbValue::Array(arr), cur))
        }
        // Boolean (14) / End Marker (13)
        14 | 13 => Ok((MmdbValue::Other, pos)),
        other => Err(ProxyError::Config(format!(
            "unsupported .mmdb data field type {other}"
        ))),
    }
}

/// Build a compact spec-compliant MaxMind DB v2.0 (`ip_version=6`, `record_size=24`) binary blob
/// from `(IpNet, ISO-3166 country code)` entries — useful for offline deterministic tests and custom `.mmdb` fixtures.
pub fn build_synthetic_country_mmdb(entries: &[(IpNet, &str)]) -> Vec<u8> {
    #[derive(Clone)]
    struct TrieNode {
        left: Option<usize>,
        right: Option<usize>,
        leaf_country: Option<String>,
    }

    let mut nodes = vec![TrieNode {
        left: None,
        right: None,
        leaf_country: None,
    }];

    for (net, code) in entries {
        let (bits_bytes, prefix_len): ([u8; 16], usize) = match net {
            IpNet::V4(v4) => {
                // MaxMind IPv6 trees store IPv4 under `::0.0.0.0/96` (`96 + prefix_len` bits)
                let mut b = [0u8; 16];
                b[12..16].copy_from_slice(&v4.network().octets());
                (b, 96 + (v4.prefix_len() as usize))
            }
            IpNet::V6(v6) => (v6.network().octets(), v6.prefix_len() as usize),
        };
        let mut cur = 0usize;
        for bit_idx in 0..prefix_len {
            let bit = (bits_bytes[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1;
            let next = if bit == 0 {
                nodes[cur].left
            } else {
                nodes[cur].right
            };
            cur = match next {
                Some(idx) => idx,
                None => {
                    let new_idx = nodes.len();
                    nodes.push(TrieNode {
                        left: None,
                        right: None,
                        leaf_country: None,
                    });
                    if bit == 0 {
                        nodes[cur].left = Some(new_idx);
                    } else {
                        nodes[cur].right = Some(new_idx);
                    }
                    new_idx
                }
            };
        }
        nodes[cur].leaf_country = Some(code.to_ascii_uppercase());
    }

    // Separate internal trie nodes from leaf country records
    // Any node with `leaf_country` becomes a data-section record; internal nodes get indices `0..internal_count`.
    let mut old_to_internal: HashMap<usize, usize> = HashMap::new();
    let mut internal_order: Vec<usize> = Vec::new();
    for (idx, n) in nodes.iter().enumerate() {
        if n.leaf_country.is_none() || idx == 0 {
            let mapped = internal_order.len();
            old_to_internal.insert(idx, mapped);
            internal_order.push(idx);
        }
    }
    let node_count = internal_order.len();

    // Build data section encoding `{ "country": { "iso_code": "<CODE>" } }` for each unique country code
    let mut data_section: Vec<u8> = Vec::new();
    let mut code_offsets: HashMap<String, usize> = HashMap::new();
    for n in &nodes {
        if let Some(ref code) = n.leaf_country
            && !code_offsets.contains_key(code)
        {
            let offset = data_section.len();
            encode_mmdb_country_record(code, &mut data_section);
            code_offsets.insert(code.clone(), offset);
        }
    }

    let resolve_child = |child: Option<usize>| -> usize {
        match child {
            None => node_count, // MaxMind empty/not-found sentinel == `node_count`
            Some(c_idx) => {
                if let Some(ref code) = nodes[c_idx].leaf_country {
                    node_count + DATA_SECTION_SEPARATOR_SIZE + code_offsets[code]
                } else {
                    old_to_internal[&c_idx]
                }
            }
        }
    };

    let mut out = Vec::with_capacity(node_count * 6 + 16 + data_section.len() + 128);
    // 24-bit record search tree (6 bytes per node)
    for &orig_idx in &internal_order {
        let left_rec = resolve_child(nodes[orig_idx].left);
        let right_rec = resolve_child(nodes[orig_idx].right);
        out.push(((left_rec >> 16) & 0xFF) as u8);
        out.push(((left_rec >> 8) & 0xFF) as u8);
        out.push((left_rec & 0xFF) as u8);
        out.push(((right_rec >> 16) & 0xFF) as u8);
        out.push(((right_rec >> 8) & 0xFF) as u8);
        out.push((right_rec & 0xFF) as u8);
    }

    // 16 zero separator bytes
    out.extend_from_slice(&[0u8; DATA_SECTION_SEPARATOR_SIZE]);
    out.extend_from_slice(&data_section);

    // Metadata marker + Metadata map
    out.extend_from_slice(MMDB_METADATA_MARKER);
    // Map of 4 pairs (`0xE4`): node_count, record_size=24, ip_version=6, database_type="GeoLite2-Country"
    out.push((7u8 << 5) | 4);
    encode_mmdb_str("node_count", &mut out);
    encode_mmdb_uint32(node_count as u32, &mut out);
    encode_mmdb_str("record_size", &mut out);
    encode_mmdb_uint16(24, &mut out);
    encode_mmdb_str("ip_version", &mut out);
    encode_mmdb_uint16(6, &mut out);
    encode_mmdb_str("database_type", &mut out);
    encode_mmdb_str("GeoLite2-Country", &mut out);

    out
}

fn encode_mmdb_country_record(iso_code: &str, out: &mut Vec<u8>) {
    // `{ "country": { "iso_code": "<iso_code>" } }`
    out.push((7u8 << 5) | 1); // Map(1)
    encode_mmdb_str("country", out);
    out.push((7u8 << 5) | 1); // Map(1)
    encode_mmdb_str("iso_code", out);
    encode_mmdb_str(iso_code, out);
}

fn encode_mmdb_str(s: &str, out: &mut Vec<u8>) {
    let b = s.as_bytes();
    assert!(b.len() <= 28, "short helper string");
    out.push((2u8 << 5) | (b.len() as u8));
    out.extend_from_slice(b);
}

fn encode_mmdb_uint16(v: u16, out: &mut Vec<u8>) {
    let bytes = v.to_be_bytes();
    let trimmed = if bytes[0] == 0 {
        &bytes[1..]
    } else {
        &bytes[..]
    };
    out.push((5u8 << 5) | (trimmed.len() as u8));
    out.extend_from_slice(trimmed);
}

fn encode_mmdb_uint32(v: u32, out: &mut Vec<u8>) {
    let bytes = v.to_be_bytes();
    let first_nz = bytes.iter().position(|&x| x != 0).unwrap_or(3);
    let trimmed = &bytes[first_nz..];
    out.push((6u8 << 5) | (trimmed.len() as u8));
    out.extend_from_slice(trimmed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmdb_v2_reader_resolves_ipv4_ipv6_and_mapped_addresses() {
        let blob = build_synthetic_country_mmdb(&[
            ("223.5.5.0/24".parse().unwrap(), "CN"),
            ("8.8.8.0/24".parse().unwrap(), "US"),
            ("133.242.0.0/16".parse().unwrap(), "JP"),
            ("2400:3200::/32".parse().unwrap(), "CN"),
            ("2606:4700::/32".parse().unwrap(), "US"),
        ]);

        let reader = MmdbReader::from_bytes(blob).unwrap();
        assert_eq!(
            reader.lookup_country_code("223.5.5.5".parse().unwrap()),
            Some("CN".to_string())
        );
        assert_eq!(
            reader.lookup_country_code("8.8.8.8".parse().unwrap()),
            Some("US".to_string())
        );
        assert_eq!(
            reader.lookup_country_code("133.242.10.20".parse().unwrap()),
            Some("JP".to_string())
        );
        assert_eq!(
            reader.lookup_country_code("2400:3200::1".parse().unwrap()),
            Some("CN".to_string())
        );
        assert_eq!(
            reader.lookup_country_code("2606:4700:4700::1111".parse().unwrap()),
            Some("US".to_string())
        );
        // IPv4-mapped IPv6 (`::ffff:223.5.5.5`) resolves to CN
        assert_eq!(
            reader.lookup_country_code("::ffff:223.5.5.5".parse().unwrap()),
            Some("CN".to_string())
        );
        assert_eq!(reader.lookup_country_code("9.9.9.9".parse().unwrap()), None);
    }
}
