use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};

use crate::error::{ProxyError, Result};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SRV: u16 = 33;
pub const QTYPE_OPT: u16 = 41;
pub const QTYPE_SVCB: u16 = 64;
pub const QTYPE_HTTPS: u16 = 65;
pub const QCLASS_IN: u16 = 1;

/// Parse a DNS record type name (`A`, `AAAA`, `TXT`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, `SVCB`, `HTTPS`, `TYPE65`)
/// or numeric `u16` string into its wire QTYPE code.
pub fn parse_qtype_str(raw: &str) -> Option<u16> {
    let upper = raw.trim().to_ascii_uppercase();
    if upper.is_empty() {
        return None;
    }
    if let Ok(num) = upper.parse::<u16>() {
        return (num > 0).then_some(num);
    }
    if let Some(rest) = upper.strip_prefix("TYPE")
        && let Ok(num) = rest.parse::<u16>()
    {
        return (num > 0).then_some(num);
    }
    match upper.as_str() {
        "A" => Some(QTYPE_A),
        "NS" => Some(QTYPE_NS),
        "CNAME" => Some(QTYPE_CNAME),
        "SOA" => Some(QTYPE_SOA),
        "PTR" => Some(QTYPE_PTR),
        "MX" => Some(QTYPE_MX),
        "TXT" => Some(QTYPE_TXT),
        "AAAA" => Some(QTYPE_AAAA),
        "SRV" => Some(QTYPE_SRV),
        "SVCB" => Some(QTYPE_SVCB),
        "HTTPS" => Some(QTYPE_HTTPS),
        _ => None,
    }
}

/// Format a numeric wire QTYPE into its canonical mnemonic (or `TYPE<N>`).
pub fn format_qtype_name(qtype: u16) -> String {
    match qtype {
        QTYPE_A => "A".to_string(),
        QTYPE_NS => "NS".to_string(),
        QTYPE_CNAME => "CNAME".to_string(),
        QTYPE_SOA => "SOA".to_string(),
        QTYPE_PTR => "PTR".to_string(),
        QTYPE_MX => "MX".to_string(),
        QTYPE_TXT => "TXT".to_string(),
        QTYPE_AAAA => "AAAA".to_string(),
        QTYPE_SRV => "SRV".to_string(),
        QTYPE_SVCB => "SVCB".to_string(),
        QTYPE_HTTPS => "HTTPS".to_string(),
        other => format!("TYPE{other}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte offset right after this question in the original packet.
    pub end_offset: usize,
}

#[derive(Clone, Debug)]
pub struct DnsQueryPacket {
    pub id: u16,
    pub flags: u16,
    pub question: DnsQuestion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsAnswerData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Txt(String),
}

impl DnsQueryPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(ProxyError::Dns(
                "DNS packet shorter than 12-byte header".into(),
            ));
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        if qdcount == 0 {
            return Err(ProxyError::Dns("DNS packet contains zero questions".into()));
        }
        let (name, pos) = decode_domain_name(buf, 12)?;
        if pos + 4 > buf.len() {
            return Err(ProxyError::Dns("truncated DNS question footer".into()));
        }
        let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        Ok(Self {
            id,
            flags,
            question: DnsQuestion {
                name,
                qtype,
                qclass,
                end_offset: pos + 4,
            },
        })
    }

    /// Build a DNS response echoing the original question and attaching zero or more answers.
    pub fn build_response(
        &self,
        raw_query: &[u8],
        rcode: u8,
        ttl: u32,
        answers: &[DnsAnswerData],
    ) -> Vec<u8> {
        let rd = self.flags & 0x0100;
        // QR=1 (0x8000), Opcode preserved, AA=0, TC=0, RD preserved, RA=1 (0x0080), RCODE=(rcode & 0x0F)
        let opcode = self.flags & 0x7800;
        let resp_flags: u16 = 0x8000 | opcode | rd | 0x0080 | u16::from(rcode & 0x0F);

        let mut out = BytesMut::with_capacity(128);
        out.put_u16(self.id);
        out.put_u16(resp_flags);
        out.put_u16(1); // QDCOUNT = 1
        out.put_u16(answers.len() as u16); // ANCOUNT
        out.put_u16(0); // NSCOUNT
        out.put_u16(0); // ARCOUNT

        // Echo the first question verbatim from raw_query[12..end_offset]
        if self.question.end_offset <= raw_query.len() && self.question.end_offset > 12 {
            out.put_slice(&raw_query[12..self.question.end_offset]);
        } else {
            encode_domain_name(&self.question.name, &mut out);
            out.put_u16(self.question.qtype);
            out.put_u16(self.question.qclass);
        }

        for ans in answers {
            // Compression pointer to offset 12 (start of QNAME)
            out.put_u16(0xC00C);
            match ans {
                DnsAnswerData::A(v4) => {
                    out.put_u16(QTYPE_A);
                    out.put_u16(QCLASS_IN);
                    out.put_u32(ttl);
                    out.put_u16(4);
                    out.put_slice(&v4.octets());
                }
                DnsAnswerData::Aaaa(v6) => {
                    out.put_u16(QTYPE_AAAA);
                    out.put_u16(QCLASS_IN);
                    out.put_u32(ttl);
                    out.put_u16(16);
                    out.put_slice(&v6.octets());
                }
                DnsAnswerData::Txt(text) => {
                    let bytes = text.as_bytes();
                    let chunk = &bytes[..bytes.len().min(255)];
                    out.put_u16(QTYPE_TXT);
                    out.put_u16(QCLASS_IN);
                    out.put_u32(ttl);
                    out.put_u16((chunk.len() + 1) as u16);
                    out.put_u8(chunk.len() as u8);
                    out.put_slice(chunk);
                }
            }
        }

        out.to_vec()
    }

    /// Build a DNS PTR response encoding `ptr_target` as uncompressed RFC 1035 domain labels.
    pub fn build_ptr_response(&self, raw_query: &[u8], ttl: u32, ptr_target: &str) -> Vec<u8> {
        let rd = self.flags & 0x0100;
        let opcode = self.flags & 0x7800;
        let resp_flags: u16 = 0x8000 | opcode | rd | 0x0080;

        let mut rdata = BytesMut::with_capacity(ptr_target.len() + 2);
        encode_domain_name(ptr_target, &mut rdata);

        let mut out = BytesMut::with_capacity(128 + rdata.len());
        out.put_u16(self.id);
        out.put_u16(resp_flags);
        out.put_u16(1); // QDCOUNT = 1
        out.put_u16(1); // ANCOUNT = 1
        out.put_u16(0); // NSCOUNT
        out.put_u16(0); // ARCOUNT

        if self.question.end_offset <= raw_query.len() && self.question.end_offset > 12 {
            out.put_slice(&raw_query[12..self.question.end_offset]);
        } else {
            encode_domain_name(&self.question.name, &mut out);
            out.put_u16(self.question.qtype);
            out.put_u16(self.question.qclass);
        }

        // Compression pointer to offset 12 (start of QNAME)
        out.put_u16(0xC00C);
        out.put_u16(QTYPE_PTR);
        out.put_u16(QCLASS_IN);
        out.put_u32(ttl);
        out.put_u16(rdata.len() as u16);
        out.put_slice(&rdata);

        out.to_vec()
    }
}

/// Build a standard recursive DNS query packet for `domain` and `qtype`.
pub fn build_dns_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(64);
    out.put_u16(id);
    out.put_u16(0x0100); // Standard query, RD=1
    out.put_u16(1); // QDCOUNT
    out.put_u16(0);
    out.put_u16(0);
    out.put_u16(0);
    encode_domain_name(domain, &mut out);
    out.put_u16(qtype);
    out.put_u16(QCLASS_IN);
    out.to_vec()
}

/// Extract the 4-bit RCODE from a DNS response packet header, validating that QR=1.
pub fn dns_response_rcode(buf: &[u8]) -> Result<u8> {
    if buf.len() < 12 {
        return Err(ProxyError::Dns("short DNS response".into()));
    }
    if (buf[2] & 0x80) == 0 {
        return Err(ProxyError::Dns(
            "DNS packet is not a response (QR=0)".into(),
        ));
    }
    Ok(buf[3] & 0x0F)
}

#[derive(Clone, Debug)]
pub struct DnsResponseMeta {
    pub rcode: u8,
    pub truncated: bool,
    pub ancount: usize,
    pub min_ttl: Option<u32>,
    pub answers: Vec<DnsAnswerData>,
    pub cname_targets: Vec<String>,
}

fn decode_txt_rdata(rdata: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut idx = 0usize;
    while idx < rdata.len() {
        let seg_len = rdata[idx] as usize;
        idx += 1;
        let end = (idx + seg_len).min(rdata.len());
        parts.push(String::from_utf8_lossy(&rdata[idx..end]).into_owned());
        idx = end;
    }
    parts.concat()
}

/// Extract RCODE, TC (truncated) bit, answer count, minimum RR TTL (across Answer and Authority SOA records),
/// CNAME targets, and IPv4/IPv6/TXT answers from a raw DNS response packet.
pub fn extract_dns_response_meta(buf: &[u8]) -> Result<DnsResponseMeta> {
    if buf.len() < 12 {
        return Err(ProxyError::Dns("short DNS response".into()));
    }
    if (buf[2] & 0x80) == 0 {
        return Err(ProxyError::Dns(
            "DNS packet is not a response (QR=0)".into(),
        ));
    }
    let rcode = buf[3] & 0x0F;
    let truncated = (buf[2] & 0x02) != 0;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = match decode_domain_name(buf, pos) {
            Ok(v) => v,
            Err(_) if truncated => {
                return Ok(DnsResponseMeta {
                    rcode,
                    truncated: true,
                    ancount,
                    min_ttl: None,
                    answers: Vec::new(),
                    cname_targets: Vec::new(),
                });
            }
            Err(e) => return Err(e),
        };
        if next + 4 > buf.len() {
            if truncated {
                return Ok(DnsResponseMeta {
                    rcode,
                    truncated: true,
                    ancount,
                    min_ttl: None,
                    answers: Vec::new(),
                    cname_targets: Vec::new(),
                });
            }
            return Err(ProxyError::Dns("truncated question in response".into()));
        }
        pos = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount.min(64));
    let mut cname_targets = Vec::new();
    let mut min_ttl: Option<u32> = None;
    let mut decoded_ancount = 0usize;

    for _ in 0..ancount {
        let (_, next) = match decode_domain_name(buf, pos) {
            Ok(v) => v,
            Err(_) if truncated => break,
            Err(e) => return Err(e),
        };
        if next + 10 > buf.len() {
            if truncated {
                break;
            }
            return Err(ProxyError::Dns("truncated RR header in response".into()));
        }
        let rtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
        let ttl = u32::from_be_bytes([buf[next + 4], buf[next + 5], buf[next + 6], buf[next + 7]]);
        let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > buf.len() {
            if truncated {
                break;
            }
            return Err(ProxyError::Dns("truncated RR rdata in response".into()));
        }
        decoded_ancount += 1;
        min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
        match rtype {
            QTYPE_A if rdlen == 4 => {
                answers.push(DnsAnswerData::A(Ipv4Addr::new(
                    buf[rdata_start],
                    buf[rdata_start + 1],
                    buf[rdata_start + 2],
                    buf[rdata_start + 3],
                )));
            }
            QTYPE_AAAA if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[rdata_start..rdata_end]);
                answers.push(DnsAnswerData::Aaaa(Ipv6Addr::from(octets)));
            }
            QTYPE_TXT => {
                answers.push(DnsAnswerData::Txt(decode_txt_rdata(
                    &buf[rdata_start..rdata_end],
                )));
            }
            QTYPE_CNAME => {
                if let Ok((cname, _)) = decode_domain_name(buf, rdata_start)
                    && !cname.is_empty()
                    && !cname_targets.contains(&cname)
                {
                    cname_targets.push(cname);
                }
            }
            _ => {}
        }
        pos = rdata_end;
    }

    // Parse Authority section briefly to capture SOA negative-caching TTL (RFC 2308) when ANCOUNT=0
    for _ in 0..nscount {
        let Ok((_, next)) = decode_domain_name(buf, pos) else {
            break;
        };
        if next + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
        let ttl = u32::from_be_bytes([buf[next + 4], buf[next + 5], buf[next + 6], buf[next + 7]]);
        let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
        let rdata_end = next + 10 + rdlen;
        if rdata_end > buf.len() {
            break;
        }
        if rtype == QTYPE_SOA {
            let mut neg_ttl = ttl;
            if rdlen >= 4 {
                let soa_minimum = u32::from_be_bytes([
                    buf[rdata_end - 4],
                    buf[rdata_end - 3],
                    buf[rdata_end - 2],
                    buf[rdata_end - 1],
                ]);
                neg_ttl = neg_ttl.min(soa_minimum);
            }
            min_ttl = Some(min_ttl.map_or(neg_ttl, |cur| cur.min(neg_ttl)));
        }
        pos = rdata_end;
    }

    Ok(DnsResponseMeta {
        rcode,
        truncated,
        ancount: decoded_ancount,
        min_ttl,
        answers,
        cname_targets,
    })
}

/// Extract IPv4/IPv6/TXT answers from a raw DNS response packet.
pub fn extract_ip_answers(buf: &[u8]) -> Result<Vec<DnsAnswerData>> {
    Ok(extract_dns_response_meta(buf)?.answers)
}

/// Extract human-readable `(record_type, data)` tuples across all Answer RRs for `/dns/query`.
pub fn extract_dns_display_answers(buf: &[u8]) -> Result<Vec<(String, String)>> {
    if buf.len() < 12 {
        return Err(ProxyError::Dns("short DNS response".into()));
    }
    if (buf[2] & 0x80) == 0 {
        return Err(ProxyError::Dns(
            "DNS packet is not a response (QR=0)".into(),
        ));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = decode_domain_name(buf, pos)?;
        if next + 4 > buf.len() {
            return Err(ProxyError::Dns("truncated question in response".into()));
        }
        pos = next + 4;
    }
    let mut out = Vec::with_capacity(ancount.min(64));
    for _ in 0..ancount {
        let Ok((_, next)) = decode_domain_name(buf, pos) else {
            break;
        };
        if next + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
        let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > buf.len() {
            break;
        }
        let rtype_name = format_qtype_name(rtype);
        let formatted = match rtype {
            QTYPE_A if rdlen == 4 => Ipv4Addr::new(
                buf[rdata_start],
                buf[rdata_start + 1],
                buf[rdata_start + 2],
                buf[rdata_start + 3],
            )
            .to_string(),
            QTYPE_AAAA if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[rdata_start..rdata_end]);
                Ipv6Addr::from(octets).to_string()
            }
            QTYPE_TXT => decode_txt_rdata(&buf[rdata_start..rdata_end]),
            QTYPE_CNAME | QTYPE_NS | QTYPE_PTR => decode_domain_name(buf, rdata_start)
                .map(|(d, _)| d)
                .unwrap_or_default(),
            QTYPE_MX if rdlen >= 3 => {
                let pref = u16::from_be_bytes([buf[rdata_start], buf[rdata_start + 1]]);
                let exch = decode_domain_name(buf, rdata_start + 2)
                    .map(|(d, _)| d)
                    .unwrap_or_default();
                format!("{pref} {exch}")
            }
            QTYPE_SRV if rdlen >= 7 => {
                let prio = u16::from_be_bytes([buf[rdata_start], buf[rdata_start + 1]]);
                let weight = u16::from_be_bytes([buf[rdata_start + 2], buf[rdata_start + 3]]);
                let port = u16::from_be_bytes([buf[rdata_start + 4], buf[rdata_start + 5]]);
                let target = decode_domain_name(buf, rdata_start + 6)
                    .map(|(d, _)| d)
                    .unwrap_or_default();
                format!("{prio} {weight} {port} {target}")
            }
            _ => {
                let mut hex = String::with_capacity(rdlen * 2);
                for &b in &buf[rdata_start..rdata_end] {
                    use std::fmt::Write as _;
                    let _ = write!(&mut hex, "{b:02x}");
                }
                hex
            }
        };
        out.push((rtype_name, formatted));
        pos = rdata_end;
    }
    Ok(out)
}

/// Build a minimal `TC=1` (Truncated) UDP DNS response echoing `raw_query`'s question so stub
/// resolvers cleanly retry over TCP `:53` when a DNS reply exceeds the UDP payload / MTU limit.
pub fn build_truncated_dns_header(raw_query: &[u8], query: &DnsQueryPacket) -> Vec<u8> {
    let rd = query.flags & 0x0100;
    let opcode = query.flags & 0x7800;
    // QR=1 (0x8000) | opcode | TC=1 (0x0200) | RD | RA=1 (0x0080)
    let resp_flags: u16 = 0x8000 | opcode | 0x0200 | rd | 0x0080;
    let mut out = BytesMut::with_capacity(64);
    out.put_u16(query.id);
    out.put_u16(resp_flags);
    out.put_u16(1); // QDCOUNT = 1
    out.put_u16(0); // ANCOUNT = 0
    out.put_u16(0); // NSCOUNT = 0
    out.put_u16(0); // ARCOUNT = 0
    if query.question.end_offset <= raw_query.len() && query.question.end_offset > 12 {
        out.put_slice(&raw_query[12..query.question.end_offset]);
    } else {
        encode_domain_name(&query.question.name, &mut out);
        out.put_u16(query.question.qtype);
        out.put_u16(query.question.qclass);
    }
    out.to_vec()
}

/// Patch a cached DNS wire response for a new caller:
/// 1. Overwrites Transaction ID (`[0..2]`) and mirrors the caller's `RD` bit (`0x0100`).
/// 2. Echoes the caller's exact Question QNAME casing (`DNS-0x20` bit randomization safe) into
///    both the Question section and any uncompressed matching RR owner names.
/// 3. Subtracts `elapsed_secs` from Answer/Authority/Additional RR TTLs (clamped to `>= 1`).
pub fn patch_cached_dns_wire_response(
    cached_wire: &[u8],
    raw_query: &[u8],
    query: &DnsQueryPacket,
    elapsed_secs: u32,
) -> Vec<u8> {
    let mut hit = cached_wire.to_vec();
    if hit.len() < 12 || raw_query.len() < 12 {
        return hit;
    }
    hit[0] = raw_query[0];
    hit[1] = raw_query[1];
    // Preserve caller's Recursion Desired (RD, bit 0 of byte 2)
    hit[2] = (hit[2] & !0x01) | (raw_query[2] & 0x01);

    let caller_q_slice = (query.question.end_offset > 12
        && query.question.end_offset <= raw_query.len())
    .then(|| &raw_query[12..query.question.end_offset]);
    let caller_qname_wire = caller_q_slice.and_then(|s| s.get(..s.len().saturating_sub(4)));

    let qdcount = u16::from_be_bytes([hit[4], hit[5]]) as usize;
    let ancount = u16::from_be_bytes([hit[6], hit[7]]) as usize;
    let nscount = u16::from_be_bytes([hit[8], hit[9]]) as usize;
    let arcount = u16::from_be_bytes([hit[10], hit[11]]) as usize;

    let mut pos = 12usize;
    for qi in 0..qdcount {
        let Ok((qname_dec, next)) = decode_domain_name(&hit, pos) else {
            return hit;
        };
        if next + 4 > hit.len() {
            return hit;
        }
        let q_end = next + 4;
        if qi == 0
            && let Some(raw_q) = caller_q_slice
            && q_end - pos == raw_q.len()
            && qname_dec.eq_ignore_ascii_case(&query.question.name)
        {
            hit[pos..q_end].copy_from_slice(raw_q);
        }
        pos = q_end;
    }

    let total_rrs = ancount.saturating_add(nscount).saturating_add(arcount);
    for _ in 0..total_rrs {
        let Ok((owner_dec, next)) = decode_domain_name(&hit, pos) else {
            break;
        };
        if next + 10 > hit.len() {
            break;
        }
        // If this RR uses an uncompressed owner name matching the queried QNAME, mirror DNS-0x20 casing too
        if let Some(raw_qname) = caller_qname_wire
            && next - pos == raw_qname.len()
            && (hit[pos] & 0xC0) == 0
            && owner_dec.eq_ignore_ascii_case(&query.question.name)
        {
            hit[pos..next].copy_from_slice(raw_qname);
        }
        let rtype = u16::from_be_bytes([hit[next], hit[next + 1]]);
        let rdlen = u16::from_be_bytes([hit[next + 8], hit[next + 9]]) as usize;
        let rdata_end = next + 10 + rdlen;
        if rdata_end > hit.len() {
            break;
        }
        // Decrement standard RR TTLs (skipping EDNS0 OPT pseudo-RR whose TTL bytes encode extended RCODE/flags)
        if rtype != QTYPE_OPT && elapsed_secs > 0 {
            let orig_ttl =
                u32::from_be_bytes([hit[next + 4], hit[next + 5], hit[next + 6], hit[next + 7]]);
            if orig_ttl > 0 {
                let rem_ttl = orig_ttl.saturating_sub(elapsed_secs).max(1);
                hit[next + 4..next + 8].copy_from_slice(&rem_ttl.to_be_bytes());
            }
        }
        pos = rdata_end;
    }

    hit
}

pub fn encode_domain_name(domain: &str, out: &mut BytesMut) {
    let clean = domain.trim().trim_matches('.');
    if clean.is_empty() {
        out.put_u8(0);
        return;
    }
    let mut wire_bytes = 1usize; // terminating root 0x00
    for label in clean.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        let len = bytes.len().min(63);
        if wire_bytes + 1 + len > 255 {
            break;
        }
        out.put_u8(len as u8);
        out.put_slice(&bytes[..len]);
        wire_bytes += 1 + len;
    }
    out.put_u8(0);
}

pub fn decode_domain_name(buf: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos = None;
    let mut jumps = 0usize;
    let mut total_wire_len = 1usize; // terminating root 0x00

    loop {
        if pos >= buf.len() {
            return Err(ProxyError::Dns("DNS name offset out of bounds".into()));
        }
        let len = buf[pos];
        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(ProxyError::Dns("truncated DNS compression pointer".into()));
            }
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            let offset = (((len & 0x3F) as usize) << 8) | (buf[pos + 1] as usize);
            if offset >= pos {
                return Err(ProxyError::Dns(
                    "invalid forward or self-referencing DNS compression pointer".into(),
                ));
            }
            jumps += 1;
            if jumps > 16 {
                return Err(ProxyError::Dns(
                    "DNS compression pointer loop detected".into(),
                ));
            }
            pos = offset;
            continue;
        }
        if (len & 0xC0) != 0 {
            return Err(ProxyError::Dns("unsupported DNS label flag".into()));
        }
        let label_len = len as usize;
        total_wire_len = total_wire_len
            .checked_add(1 + label_len)
            .filter(|&n| n <= 255)
            .ok_or_else(|| ProxyError::Dns("DNS domain name exceeds 255 octets".into()))?;
        pos += 1;
        if pos + label_len > buf.len() {
            return Err(ProxyError::Dns("truncated DNS label".into()));
        }
        let label = std::str::from_utf8(&buf[pos..pos + label_len])
            .map_err(|_| ProxyError::Dns("invalid UTF-8 in DNS label".into()))?
            .to_ascii_lowercase();
        labels.push(label);
        pos += label_len;
    }

    Ok((labels.join("."), end_pos.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_rejects_forward_and_self_compression_pointers_and_overlong_names() {
        // Self-referencing pointer at offset 12 (`0xC0 0x0C`)
        let mut self_ptr = vec![0u8; 12];
        self_ptr.extend_from_slice(&[0xC0, 0x0C]);
        assert!(decode_domain_name(&self_ptr, 12).is_err());

        // Forward pointer at offset 12 pointing to offset 16 (`0xC0 0x10`)
        let mut fwd_ptr = vec![0u8; 12];
        fwd_ptr.extend_from_slice(&[0xC0, 0x10, 0x03, b'c', b'o', b'm', 0x00]);
        assert!(decode_domain_name(&fwd_ptr, 12).is_err());

        // Overlong domain > 255 octets on wire is truncated safely at encode time and parses cleanly
        let overlong_domain = format!(
            "{}.{}.{}.{}.example.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        let q = build_dns_query(0x1234, &overlong_domain, QTYPE_A);
        let parsed = DnsQueryPacket::parse(&q).unwrap();
        assert_eq!(parsed.question.qtype, QTYPE_A);
        assert!(parsed.question.name.len() <= 253);
    }

    #[test]
    fn wire_extracts_rcode_and_cname_chain_answers() {
        let q = build_dns_query(0x4242, "alias.example.com", QTYPE_A);
        let parsed_q = DnsQueryPacket::parse(&q).unwrap();
        let servfail = parsed_q.build_response(&q, 2, 0, &[]);
        assert_eq!(dns_response_rcode(&servfail).unwrap(), 2);

        // Build synthetic DNS response with CNAME alias.example.com -> real.example.com + A 93.184.216.34
        let mut pkt = BytesMut::new();
        pkt.put_u16(0x4242);
        pkt.put_u16(0x8180); // QR=1, RCODE=0
        pkt.put_u16(1); // QDCOUNT
        pkt.put_u16(2); // ANCOUNT
        pkt.put_u16(0);
        pkt.put_u16(0);
        encode_domain_name("alias.example.com", &mut pkt);
        pkt.put_u16(QTYPE_A);
        pkt.put_u16(QCLASS_IN);

        // Answer 1: CNAME -> real.example.com
        encode_domain_name("alias.example.com", &mut pkt);
        pkt.put_u16(QTYPE_CNAME);
        pkt.put_u16(QCLASS_IN);
        pkt.put_u32(120);
        let mut cname_rdata = BytesMut::new();
        encode_domain_name("real.example.com", &mut cname_rdata);
        pkt.put_u16(cname_rdata.len() as u16);
        pkt.put_slice(&cname_rdata);

        // Answer 2: A real.example.com -> 93.184.216.34
        encode_domain_name("real.example.com", &mut pkt);
        pkt.put_u16(QTYPE_A);
        pkt.put_u16(QCLASS_IN);
        pkt.put_u32(60);
        pkt.put_u16(4);
        pkt.put_slice(&Ipv4Addr::new(93, 184, 216, 34).octets());

        let meta = extract_dns_response_meta(&pkt).unwrap();
        assert_eq!(meta.rcode, 0);
        assert_eq!(meta.ancount, 2);
        assert_eq!(meta.cname_targets, vec!["real.example.com".to_string()]);
        assert_eq!(meta.min_ttl, Some(60));
        assert_eq!(
            meta.answers,
            vec![DnsAnswerData::A(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn wire_decodes_txt_formats_display_answers_and_patches_dns0x20_and_ttl() {
        assert_eq!(parse_qtype_str("TXT"), Some(QTYPE_TXT));
        assert_eq!(parse_qtype_str("https"), Some(QTYPE_HTTPS));
        assert_eq!(parse_qtype_str("65"), Some(65));
        assert_eq!(format_qtype_name(QTYPE_HTTPS), "HTTPS");

        // Build response with uncompressed answer owner name + multi-segment TXT RDATA + OPT RR
        let mut resp = BytesMut::new();
        resp.put_u16(0x1111);
        resp.put_u16(0x8180); // QR=1, RD=1, RA=1
        resp.put_u16(1); // QDCOUNT
        resp.put_u16(1); // ANCOUNT
        resp.put_u16(0); // NSCOUNT
        resp.put_u16(1); // ARCOUNT (EDNS0 OPT)
        encode_domain_name("example.com", &mut resp);
        resp.put_u16(QTYPE_TXT);
        resp.put_u16(QCLASS_IN);

        // Uncompressed owner `example.com` with TTL 120 and two TXT character-strings: "v=spf1 " + "-all"
        encode_domain_name("example.com", &mut resp);
        resp.put_u16(QTYPE_TXT);
        resp.put_u16(QCLASS_IN);
        resp.put_u32(120);
        let txt_rdata = [
            7, b'v', b'=', b's', b'p', b'f', b'1', b' ', 4, b'-', b'a', b'l', b'l',
        ];
        resp.put_u16(txt_rdata.len() as u16);
        resp.put_slice(&txt_rdata);

        // EDNS0 OPT RR (`NAME = 0x00`, `TYPE = 41`, extended RCODE/flags in TTL field `0x0000_8000` must NOT be decremented!)
        resp.put_u8(0);
        resp.put_u16(QTYPE_OPT);
        resp.put_u16(1232);
        resp.put_u32(0x0000_8000);
        resp.put_u16(0);

        let meta = extract_dns_response_meta(&resp).unwrap();
        assert_eq!(meta.ancount, 1);
        assert_eq!(
            meta.answers,
            vec![DnsAnswerData::Txt("v=spf1 -all".to_string())]
        );
        assert_eq!(
            extract_dns_display_answers(&resp).unwrap(),
            vec![("TXT".to_string(), "v=spf1 -all".to_string())]
        );

        // Build a DNS-0x20 mixed-case query with RD=0 and TXID=0x99AA
        let mut q_0x20 = build_dns_query(0x99AA, "ExAmPlE.CoM", QTYPE_TXT);
        q_0x20[2] &= !0x01; // Clear RD bit
        let parsed_0x20 = DnsQueryPacket::parse(&q_0x20).unwrap();

        let patched = patch_cached_dns_wire_response(&resp, &q_0x20, &parsed_0x20, 45);
        assert_eq!(u16::from_be_bytes([patched[0], patched[1]]), 0x99AA);
        assert_eq!(patched[2] & 0x01, 0, "query RD=0 must be preserved");
        // Question QNAME bytes must match DNS-0x20 casing `ExAmPlE.CoM`
        assert_eq!(&patched[12..25], &q_0x20[12..25]);
        // Uncompressed Answer owner name (at offset 29..42) must also mirror `ExAmPlE.CoM`
        assert_eq!(&patched[29..42], &q_0x20[12..25]);
        // Answer TTL (at offset 46..50) must be decremented 120 - 45 = 75
        assert_eq!(
            u32::from_be_bytes([patched[46], patched[47], patched[48], patched[49]]),
            75
        );
        // OPT RR extended flags TTL field at tail must remain untouched (`0x0000_8000`)
        let opt_ttl_off = patched.len() - 6;
        assert_eq!(
            u32::from_be_bytes([
                patched[opt_ttl_off],
                patched[opt_ttl_off + 1],
                patched[opt_ttl_off + 2],
                patched[opt_ttl_off + 3]
            ]),
            0x0000_8000
        );

        // Truncated header helper sets QR=1 and TC=1 while preserving question section
        let tc_pkt = build_truncated_dns_header(&q_0x20, &parsed_0x20);
        let tc_meta = extract_dns_response_meta(&tc_pkt).unwrap();
        assert!(tc_meta.truncated);
        assert_eq!(&tc_pkt[12..25], &q_0x20[12..25]);
    }
}
