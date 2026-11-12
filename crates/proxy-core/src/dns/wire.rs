use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};

use crate::error::{ProxyError, Result};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SVCB: u16 = 64;
pub const QTYPE_HTTPS: u16 = 65;
pub const QCLASS_IN: u16 = 1;

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

pub const QTYPE_SOA: u16 = 6;

#[derive(Clone, Debug)]
pub struct DnsResponseMeta {
    pub rcode: u8,
    pub truncated: bool,
    pub min_ttl: Option<u32>,
    pub answers: Vec<DnsAnswerData>,
}

/// Extract RCODE, TC (truncated) bit, minimum RR TTL (across Answer and Authority SOA records),
/// and IPv4/IPv6 answers from a raw DNS response packet.
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
        let (_, next) = decode_domain_name(buf, pos)?;
        if next + 4 > buf.len() {
            return Err(ProxyError::Dns("truncated question in response".into()));
        }
        pos = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount);
    let mut min_ttl: Option<u32> = None;

    for _ in 0..ancount {
        let (_, next) = decode_domain_name(buf, pos)?;
        if next + 10 > buf.len() {
            return Err(ProxyError::Dns("truncated RR header in response".into()));
        }
        let rtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
        let ttl = u32::from_be_bytes([buf[next + 4], buf[next + 5], buf[next + 6], buf[next + 7]]);
        let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > buf.len() {
            return Err(ProxyError::Dns("truncated RR rdata in response".into()));
        }
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
        min_ttl,
        answers,
    })
}

/// Extract IPv4/IPv6 answers from a raw DNS response packet.
pub fn extract_ip_answers(buf: &[u8]) -> Result<Vec<DnsAnswerData>> {
    Ok(extract_dns_response_meta(buf)?.answers)
}

pub fn encode_domain_name(domain: &str, out: &mut BytesMut) {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() {
        out.put_u8(0);
        return;
    }
    for label in clean.split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.put_u8(len as u8);
        out.put_slice(&bytes[..len]);
    }
    out.put_u8(0);
}

pub fn decode_domain_name(buf: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos = None;
    let mut jumps = 0usize;

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
