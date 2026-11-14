use std::{net::IpAddr, sync::OnceLock};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Sorted, merged IPv4 `(start_u32, end_u32)` and IPv6 `(start_u128, end_u128)` interval set
/// enabling O(log N) GeoIP lookups without false-positive `/5`..`/8` supernets.
#[derive(Clone, Debug, Default)]
pub struct GeoIpMatcher {
    v4_ranges: Vec<(u32, u32)>,
    v6_ranges: Vec<(u128, u128)>,
}

impl GeoIpMatcher {
    pub fn from_cidrs(cidrs: &[&str]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for raw in cidrs {
            if let Ok(net) = raw.parse::<IpNet>() {
                match net {
                    IpNet::V4(n4) => v4.push(v4_bounds(n4)),
                    IpNet::V6(n6) => v6.push(v6_bounds(n6)),
                }
            }
        }
        Self {
            v4_ranges: merge_v4(v4),
            v6_ranges: merge_v6(v6),
        }
    }

    /// Parse plain CIDR lists, Clash YAML `payload:` ipcidr rule-sets, or classical `IP-CIDR`/`IP-CIDR6` lines.
    pub fn from_cidr_text(text: &str) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for raw_line in text.lines() {
            let mut line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.eq_ignore_ascii_case("payload:") {
                continue;
            }
            if let Some(rest) = line.strip_prefix('-') {
                line = rest.trim();
            }
            line = line.trim_matches('\'').trim_matches('"').trim();
            if let Some((before_comment, _)) = line.split_once('#') {
                line = before_comment.trim();
            }
            if line.is_empty() {
                continue;
            }
            let cidr_token = if let Some((kind, rest)) = line.split_once(',') {
                let kind_up = kind.trim().to_ascii_uppercase();
                if matches!(kind_up.as_str(), "IP-CIDR" | "IP-CIDR6") {
                    rest.split(',').next().unwrap_or(rest).trim()
                } else {
                    continue;
                }
            } else {
                line
            };
            let cidr_token = cidr_token.trim_matches('\'').trim_matches('"').trim();
            if let Ok(net) = cidr_token.parse::<IpNet>() {
                match net {
                    IpNet::V4(n4) => v4.push(v4_bounds(n4)),
                    IpNet::V6(n6) => v6.push(v6_bounds(n6)),
                }
            } else if let Ok(ip) = cidr_token.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(ip4) => {
                        let u = u32::from(ip4);
                        v4.push((u, u));
                    }
                    IpAddr::V6(ip6) => {
                        let u = u128::from(ip6);
                        v6.push((u, u));
                    }
                }
            }
        }
        Self {
            v4_ranges: merge_v4(v4),
            v6_ranges: merge_v6(v6),
        }
    }

    pub fn merged_with(&self, extra: &GeoIpMatcher) -> Self {
        let mut v4 = self.v4_ranges.clone();
        v4.extend_from_slice(&extra.v4_ranges);
        let mut v6 = self.v6_ranges.clone();
        v6.extend_from_slice(&extra.v6_ranges);
        Self {
            v4_ranges: merge_v4(v4),
            v6_ranges: merge_v6(v6),
        }
    }

    pub fn range_count(&self) -> usize {
        self.v4_ranges.len() + self.v6_ranges.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let target = u32::from(v4);
                let idx = self
                    .v4_ranges
                    .partition_point(|&(start, _)| start <= target);
                idx > 0 && target <= self.v4_ranges[idx - 1].1
            }
            IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    return self.contains(IpAddr::V4(mapped));
                }
                let target = u128::from(v6);
                let idx = self
                    .v6_ranges
                    .partition_point(|&(start, _)| start <= target);
                idx > 0 && target <= self.v6_ranges[idx - 1].1
            }
        }
    }
}

fn v4_bounds(net: Ipv4Net) -> (u32, u32) {
    (u32::from(net.network()), u32::from(net.broadcast()))
}

fn v6_bounds(net: Ipv6Net) -> (u128, u128) {
    (u128::from(net.network()), u128::from(net.broadcast()))
}

fn merge_v4(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut()
            && s <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(e);
            continue;
        }
        merged.push((s, e));
    }
    merged
}

fn merge_v6(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut()
            && s <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(e);
            continue;
        }
        merged.push((s, e));
    }
    merged
}

/// Look up a built-in `GeoIpMatcher` by uppercase country/category code.
/// Returns `None` for unsupported codes so config validation rejects typos/missing databases explicitly.
pub fn lookup_builtin_geoip(code: &str) -> Option<&'static GeoIpMatcher> {
    static PRIVATE: OnceLock<GeoIpMatcher> = OnceLock::new();
    static CN: OnceLock<GeoIpMatcher> = OnceLock::new();
    static HK: OnceLock<GeoIpMatcher> = OnceLock::new();
    static TW: OnceLock<GeoIpMatcher> = OnceLock::new();
    static JP: OnceLock<GeoIpMatcher> = OnceLock::new();
    static SG: OnceLock<GeoIpMatcher> = OnceLock::new();
    static US: OnceLock<GeoIpMatcher> = OnceLock::new();
    static CLOUDFLARE: OnceLock<GeoIpMatcher> = OnceLock::new();
    static GOOGLE: OnceLock<GeoIpMatcher> = OnceLock::new();
    static TELEGRAM: OnceLock<GeoIpMatcher> = OnceLock::new();

    match code {
        "PRIVATE" | "LAN" => Some(PRIVATE.get_or_init(|| GeoIpMatcher::from_cidrs(PRIVATE_CIDRS))),
        "CN" => Some(CN.get_or_init(|| GeoIpMatcher::from_cidrs(CN_CIDRS))),
        "HK" => Some(HK.get_or_init(|| GeoIpMatcher::from_cidrs(HK_CIDRS))),
        "TW" => Some(TW.get_or_init(|| GeoIpMatcher::from_cidrs(TW_CIDRS))),
        "JP" => Some(JP.get_or_init(|| GeoIpMatcher::from_cidrs(JP_CIDRS))),
        "SG" => Some(SG.get_or_init(|| GeoIpMatcher::from_cidrs(SG_CIDRS))),
        "US" => Some(US.get_or_init(|| GeoIpMatcher::from_cidrs(US_CIDRS))),
        "CLOUDFLARE" => Some(CLOUDFLARE.get_or_init(|| GeoIpMatcher::from_cidrs(CLOUDFLARE_CIDRS))),
        "GOOGLE" => Some(GOOGLE.get_or_init(|| GeoIpMatcher::from_cidrs(GOOGLE_CIDRS))),
        "TELEGRAM" => Some(TELEGRAM.get_or_init(|| GeoIpMatcher::from_cidrs(TELEGRAM_CIDRS))),
        _ => None,
    }
}

const PRIVATE_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// Curated APNIC Mainland China (`CN`) IPv4 & IPv6 allocations (China Telecom, Unicom, Mobile,
/// CERNET/CSTNET, Alibaba Cloud CN, Tencent Cloud CN, Baidu, Huawei Cloud CN, public CN DNS)
/// without `/5`..`/8` supernets that would misclassify JP/KR/HK/TW/SG/IN traffic.
const CN_CIDRS: &[&str] = &[
    "1.0.1.0/24",
    "1.0.2.0/23",
    "1.0.8.0/21",
    "1.0.32.0/19",
    "1.1.0.0/24",
    "1.1.2.0/23",
    "1.1.4.0/22",
    "1.1.8.0/21",
    "1.2.0.0/22",
    "1.2.4.0/24",
    "1.2.8.0/21",
    "1.4.1.0/24",
    "1.4.2.0/23",
    "1.4.4.0/22",
    "1.8.0.0/16",
    "1.12.0.0/14",
    "1.24.0.0/13",
    "1.48.0.0/15",
    "1.56.0.0/13",
    "1.68.0.0/14",
    "1.80.0.0/13",
    "1.92.0.0/14",
    "1.116.0.0/14",
    "1.180.0.0/14",
    "1.192.0.0/13",
    "1.202.0.0/15",
    "1.204.0.0/14",
    "14.16.0.0/12",
    "14.104.0.0/13",
    "14.112.0.0/12",
    "14.144.0.0/12",
    "14.196.0.0/14",
    "14.204.0.0/14",
    "14.208.0.0/12",
    "27.8.0.0/13",
    "27.16.0.0/12",
    "27.36.0.0/14",
    "27.40.0.0/13",
    "27.128.0.0/15",
    "27.148.0.0/14",
    "27.152.0.0/13",
    "27.184.0.0/13",
    "27.192.0.0/11",
    "27.224.0.0/14",
    "36.0.0.0/14",
    "36.4.0.0/14",
    "36.16.0.0/12",
    "36.32.0.0/14",
    "36.40.0.0/13",
    "36.48.0.0/13",
    "36.56.0.0/13",
    "36.64.0.0/14",
    "36.96.0.0/11",
    "36.128.0.0/10",
    "36.192.0.0/11",
    "36.248.0.0/14",
    "39.64.0.0/11",
    "39.96.0.0/13",
    "39.104.0.0/14",
    "39.128.0.0/10",
    "42.4.0.0/14",
    "42.48.0.0/13",
    "42.56.0.0/14",
    "42.80.0.0/13",
    "42.88.0.0/13",
    "42.96.0.0/14",
    "42.120.0.0/15",
    "42.122.0.0/15",
    "42.176.0.0/13",
    "42.184.0.0/14",
    "42.192.0.0/15",
    "42.224.0.0/12",
    "42.240.0.0/13",
    "43.240.0.0/14",
    "45.112.0.0/14",
    "47.92.0.0/14",
    "47.96.0.0/11",
    "49.4.0.0/14",
    "49.64.0.0/11",
    "49.112.0.0/13",
    "49.120.0.0/14",
    "49.140.0.0/15",
    "49.220.0.0/14",
    "49.232.0.0/14",
    "58.16.0.0/13",
    "58.24.0.0/14",
    "58.32.0.0/11",
    "58.66.0.0/15",
    "58.68.128.0/17",
    "58.82.0.0/15",
    "58.100.0.0/15",
    "58.192.0.0/11",
    "58.208.0.0/12",
    "58.240.0.0/12",
    "59.32.0.0/11",
    "59.64.0.0/12",
    "59.80.0.0/14",
    "59.108.0.0/15",
    "59.110.0.0/15",
    "59.172.0.0/14",
    "60.0.0.0/11",
    "60.160.0.0/11",
    "60.192.0.0/11",
    "60.208.0.0/12",
    "61.48.0.0/13",
    "61.128.0.0/10",
    "61.240.0.0/14",
    "81.68.0.0/15",
    "101.4.0.0/14",
    "101.16.0.0/12",
    "101.36.0.0/14",
    "101.64.0.0/11",
    "101.96.0.0/13",
    "101.132.0.0/15",
    "101.200.0.0/15",
    "101.224.0.0/12",
    "106.2.0.0/15",
    "106.4.0.0/14",
    "106.8.0.0/13",
    "106.16.0.0/12",
    "106.32.0.0/11",
    "106.80.0.0/12",
    "106.112.0.0/12",
    "106.120.0.0/13",
    "110.6.0.0/15",
    "110.16.0.0/13",
    "110.52.0.0/15",
    "110.64.0.0/13",
    "110.80.0.0/13",
    "110.88.0.0/14",
    "110.96.0.0/11",
    "110.152.0.0/13",
    "110.176.0.0/12",
    "110.192.0.0/11",
    "110.228.0.0/14",
    "110.240.0.0/12",
    "111.0.0.0/10",
    "111.128.0.0/11",
    "111.160.0.0/11",
    "111.192.0.0/11",
    "111.224.0.0/14",
    "112.0.0.0/10",
    "112.64.0.0/11",
    "112.96.0.0/12",
    "112.112.0.0/13",
    "112.124.0.0/14",
    "113.0.0.0/11",
    "113.64.0.0/10",
    "113.128.0.0/11",
    "113.192.0.0/11",
    "114.55.0.0/16",
    "114.80.0.0/12",
    "114.96.0.0/13",
    "114.112.0.0/13",
    "114.212.0.0/14",
    "114.216.0.0/13",
    "114.240.0.0/12",
    "115.24.0.0/14",
    "115.28.0.0/15",
    "115.48.0.0/12",
    "115.148.0.0/14",
    "115.152.0.0/13",
    "115.192.0.0/11",
    "115.224.0.0/12",
    "116.1.0.0/16",
    "116.16.0.0/12",
    "116.52.0.0/14",
    "116.62.0.0/16",
    "116.76.0.0/15",
    "116.112.0.0/13",
    "116.128.0.0/10",
    "116.192.0.0/11",
    "116.224.0.0/12",
    "117.8.0.0/13",
    "117.21.0.0/16",
    "117.24.0.0/13",
    "117.32.0.0/12",
    "117.60.0.0/14",
    "117.64.0.0/11",
    "117.128.0.0/10",
    "118.24.0.0/15",
    "118.31.0.0/16",
    "118.72.0.0/13",
    "118.88.0.0/16",
    "118.112.0.0/13",
    "118.120.0.0/14",
    "118.144.0.0/14",
    "118.178.0.0/16",
    "118.180.0.0/14",
    "118.248.0.0/13",
    "119.0.0.0/13",
    "119.23.0.0/16",
    "119.28.0.0/15",
    "119.32.0.0/12",
    "119.48.0.0/13",
    "119.57.0.0/16",
    "119.78.0.0/15",
    "119.84.0.0/14",
    "119.96.0.0/13",
    "119.112.0.0/13",
    "119.120.0.0/13",
    "119.128.0.0/12",
    "119.144.0.0/13",
    "119.162.0.0/15",
    "119.164.0.0/14",
    "119.176.0.0/12",
    "119.248.0.0/14",
    "120.24.0.0/14",
    "120.32.0.0/13",
    "120.40.0.0/14",
    "120.52.0.0/14",
    "120.76.0.0/14",
    "120.192.0.0/10",
    "121.8.0.0/13",
    "121.16.0.0/12",
    "121.32.0.0/13",
    "121.40.0.0/14",
    "122.64.0.0/11",
    "122.96.0.0/13",
    "122.224.0.0/12",
    "123.4.0.0/14",
    "123.56.0.0/14",
    "123.112.0.0/12",
    "123.128.0.0/11",
    "123.150.0.0/15",
    "124.16.0.0/15",
    "124.64.0.0/14",
    "124.72.0.0/13",
    "124.88.0.0/13",
    "124.112.0.0/13",
    "124.126.0.0/15",
    "124.128.0.0/13",
    "124.160.0.0/14",
    "124.192.0.0/14",
    "124.200.0.0/13",
    "124.220.0.0/14",
    "124.224.0.0/12",
    "125.32.0.0/12",
    "125.64.0.0/11",
    "125.112.0.0/12",
    "139.196.0.0/15",
    "139.224.0.0/14",
    "140.205.0.0/16",
    "140.206.0.0/15",
    "150.158.0.0/16",
    "163.177.0.0/16",
    "171.8.0.0/13",
    "171.34.0.0/15",
    "171.36.0.0/14",
    "171.40.0.0/13",
    "171.80.0.0/12",
    "171.104.0.0/13",
    "171.112.0.0/12",
    "171.208.0.0/12",
    "175.0.0.0/12",
    "175.16.0.0/12",
    "175.42.0.0/15",
    "175.44.0.0/15",
    "175.148.0.0/14",
    "175.152.0.0/14",
    "175.160.0.0/12",
    "180.76.0.0/16",
    "180.96.0.0/11",
    "180.136.0.0/13",
    "180.152.0.0/13",
    "180.160.0.0/12",
    "182.32.0.0/12",
    "182.61.0.0/16",
    "182.80.0.0/12",
    "182.92.0.0/16",
    "182.96.0.0/11",
    "182.128.0.0/11",
    "182.240.0.0/13",
    "183.0.0.0/10",
    "183.64.0.0/13",
    "183.128.0.0/11",
    "183.160.0.0/12",
    "183.184.0.0/13",
    "183.192.0.0/11",
    "183.224.0.0/11",
    "202.96.0.0/12",
    "202.112.0.0/13",
    "203.119.0.0/16",
    "203.205.128.0/17",
    "210.12.0.0/15",
    "210.21.0.0/16",
    "211.64.0.0/13",
    "211.80.0.0/13",
    "211.90.0.0/15",
    "211.92.0.0/14",
    "211.96.0.0/13",
    "211.136.0.0/13",
    "211.144.0.0/14",
    "218.0.0.0/11",
    "218.56.0.0/13",
    "218.64.0.0/11",
    "218.104.0.0/14",
    "218.192.0.0/12",
    "218.200.0.0/13",
    "219.128.0.0/11",
    "220.112.0.0/14",
    "220.160.0.0/11",
    "220.192.0.0/12",
    "221.0.0.0/12",
    "221.176.0.0/12",
    "221.192.0.0/11",
    "221.224.0.0/12",
    "222.16.0.0/12",
    "222.32.0.0/11",
    "222.64.0.0/11",
    "222.128.0.0/12",
    "222.168.0.0/13",
    "222.176.0.0/12",
    "222.208.0.0/12",
    "222.240.0.0/13",
    "223.0.0.0/12",
    "223.64.0.0/11",
    "223.96.0.0/12",
    "223.112.0.0/14",
    "223.166.0.0/15",
    "223.240.0.0/13",
    "2001:250::/32",
    "2001:da8::/32",
    "2400:3200::/32",
    "2400:da00::/32",
    "2402:4e00::/32",
    "2404:f340::/32",
    "2408:8000::/20",
    "2409:8000::/20",
    "240c::/20",
    "240e::/18",
];

const HK_CIDRS: &[&str] = &[
    "14.0.128.0/17",
    "42.2.0.0/15",
    "58.152.0.0/15",
    "59.148.0.0/15",
    "61.238.0.0/15",
    "203.198.0.0/16",
    "218.102.0.0/15",
];

const TW_CIDRS: &[&str] = &[
    "1.160.0.0/12",
    "36.224.0.0/12",
    "59.124.0.0/14",
    "60.248.0.0/13",
    "114.32.0.0/12",
    "220.128.0.0/11",
];

const JP_CIDRS: &[&str] = &[
    "14.8.0.0/13",
    "27.80.0.0/12",
    "49.96.0.0/12",
    "60.32.0.0/11",
    "106.128.0.0/10",
    "126.0.0.0/8",
    "133.0.0.0/8",
    "210.128.0.0/11",
];

const SG_CIDRS: &[&str] = &[
    "101.127.0.0/16",
    "116.14.0.0/15",
    "118.200.0.0/15",
    "119.81.0.0/16",
    "175.156.0.0/14",
];

const US_CIDRS: &[&str] = &[
    "3.0.0.0/9",
    "8.8.4.0/24",
    "8.8.8.0/24",
    "8.34.208.0/20",
    "8.35.192.0/20",
    "13.32.0.0/12",
    "34.64.0.0/10",
    "35.184.0.0/13",
    "52.0.0.0/11",
    "54.144.0.0/12",
    "140.82.112.0/20",
];

const CLOUDFLARE_CIDRS: &[&str] = &[
    "1.1.1.0/24",
    "1.0.0.0/24",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "2606:4700::/32",
];

const GOOGLE_CIDRS: &[&str] = &[
    "8.8.8.0/24",
    "8.8.4.0/24",
    "142.250.0.0/15",
    "172.217.0.0/16",
    "216.58.192.0/19",
    "2001:4860::/32",
];

const TELEGRAM_CIDRS: &[&str] = &[
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
    "2001:b28:f23d::/48",
    "2001:67c:4e8::/48",
];

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn builtin_jp_and_us_cidrs_avoid_cn_and_apac_supernet_false_positives() {
        let cn = lookup_builtin_geoip("CN").unwrap();
        let jp = lookup_builtin_geoip("JP").unwrap();
        let us = lookup_builtin_geoip("US").unwrap();

        // NTT Docomo (49.96.0.0/12) & KDDI (106.128.0.0/10) match JP, while CN 49.112/13 & 49.120/14 do not.
        assert!(jp.contains(IpAddr::V4(Ipv4Addr::new(49, 96, 0, 1))));
        assert!(jp.contains(IpAddr::V4(Ipv4Addr::new(106, 128, 0, 1))));
        assert!(!jp.contains(IpAddr::V4(Ipv4Addr::new(49, 112, 0, 1))));
        assert!(!jp.contains(IpAddr::V4(Ipv4Addr::new(49, 120, 0, 1))));
        assert!(!jp.contains(IpAddr::V4(Ipv4Addr::new(106, 192, 0, 1))));
        assert!(cn.contains(IpAddr::V4(Ipv4Addr::new(49, 112, 0, 1))));
        assert!(cn.contains(IpAddr::V4(Ipv4Addr::new(49, 120, 0, 1))));

        // Ensure zero IPv4 range overlap between built-in CN and JP tables.
        for &(cn_s, cn_e) in &cn.v4_ranges {
            for &(jp_s, jp_e) in &jp.v4_ranges {
                assert!(
                    cn_e < jp_s || jp_e < cn_s,
                    "CN range {cn_s}..={cn_e} overlaps JP range {jp_s}..={jp_e}"
                );
            }
        }

        // Google US DNS remains in US, while non-US 8.x allocations (e.g. 8.210.0.1) are excluded.
        assert!(us.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(us.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))));
        assert!(!us.contains(IpAddr::V4(Ipv4Addr::new(8, 210, 0, 1))));
    }
}
