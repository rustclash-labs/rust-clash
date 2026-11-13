use std::{
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use proptest::prelude::*;
use proxy_core::{
    config::{
        ClashConfig, ProxyGroupType, ProxyNodeConfig,
        uri::{
            export_proxy_uri, parse_proxy_uri, parse_subscription_uris_best_effort,
            redact_sensitive_text,
        },
    },
    profile::{
        ImportInputKind, ProfileManager, classify_import_input, fetch_subscription_http,
        parse_subscription_payload_sanitized, validate_profile_config,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct TempTestDir(PathBuf);

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rc-wild-sub-{prefix}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const CANARY_UUID: &str = "deadbeef-1234-4567-89ab-cdef01234567";
const CANARY_PASS: &str = "CanarySecretPass_X99!";
const CANARY_TOKEN: &str = "CanarySubToken_Z88";

fn assert_zero_secret_leak(text: &str) {
    assert!(
        !text.contains(CANARY_UUID),
        "leaked canary UUID in diagnostic: {text}"
    );
    assert!(
        !text.contains(CANARY_PASS),
        "leaked canary password in diagnostic: {text}"
    );
    assert!(
        !text.contains(CANARY_TOKEN),
        "leaked canary token in diagnostic: {text}"
    );
}

#[test]
fn wild_mihomo_v2board_xboard_nested_anchors_merges_bom_crlf_and_cycles() {
    // Simulates a real-world Mihomo / Clash Verge / V2Board / Xboard subscription template:
    // - UTF-8 BOM (`\u{feff}`) + multi-document `---` + CRLF (`\r\n`)
    // - Multi-level nested YAML anchors (`&base_tls` -> `&trojan_ws` -> `<<: *trojan_ws`)
    // - `sni` + `servername` and `network` + `transport` alias pairs (previously caused duplicate field error!)
    // - `security: tls`, `allow-insecure: true`, top-level `ws-path` / `ws-headers`
    // - `mixed-port: 9090` colliding with `external-controller: :9090`
    // - `proxy-groups` with `"300s"` string intervals, `include-all-providers: true`, `exclude-type: ss`,
    //   `filter` without `proxies:`, unknown group type `smart`, and a cyclic `GroupA <-> GroupB` loop
    // - `rule-providers` with a missing local `file` provider (pruned cleanly) + inline classical/ipcidr
    // - `SRC-PORT`, `NETWORK,udp,REJECT`, `GEOSITE,apple@cn,DIRECT`, bare IP `IP-CIDR,203.0.113.10,DIRECT`
    let raw_template = concat!(
        "\u{feff}---\r\n",
        "mixed-port: 9090\r\n",
        "bind-address: \"[::]\"\r\n",
        "external-controller: :9090\r\n",
        "mode: script\r\n",
        "dns:\r\n",
        "  enable: \"true\"\r\n",
        "  listen: :53\r\n",
        "  enhanced-mode: mapping\r\n",
        "  fake-ip-range:\r\n",
        "    - fc00::/18\r\n",
        "    - 198.18.0.1/16\r\n",
        "  nameserver:\r\n",
        "    - HTTPS://dns.alidns.com/dns-query\r\n",
        "    - tls://2400:3200::1\r\n",
        "base-anchor: &base_tls\r\n",
        "  tls: true\r\n",
        "  allow-insecure: false\r\n",
        "  udp: true\r\n",
        "ws-anchor: &trojan_ws\r\n",
        "  <<: *base_tls\r\n",
        "  type: trojan\r\n",
        "  network: ws\r\n",
        "  transport: ws\r\n",
        "  ws-path: /edge-ws?ed=2048\r\n",
        "  ws-headers:\r\n",
        "    Host: cdn.example.com\r\n",
        "proxies:\r\n",
        "  - name: \"🇭🇰 HK-IPLC-01\"\r\n",
        "    <<: *trojan_ws\r\n",
        "    server: \"[2001:db8::10]\"\r\n",
        "    port: \"443\"\r\n",
        "    password: \"CanarySecretPass_X99!\"\r\n",
        "    sni: hk.example.com\r\n",
        "    servername: cdn.example.com\r\n",
        "  - name: \"🇯🇵 JP-VLESS-01\"\r\n",
        "    type: vless\r\n",
        "    server: jp.example.com\r\n",
        "    port: 443\r\n",
        "    uuid: deadbeef-1234-4567-89ab-cdef01234567\r\n",
        "    security: tls\r\n",
        "    peer: jp.example.com\r\n",
        "    client-fingerprint: chrome\r\n",
        "  - name: \"🇸🇬 SG-SS-01\"\r\n",
        "    type: ss\r\n",
        "    server: sg.example.com\r\n",
        "    port: 8388\r\n",
        "    cipher: 2022-blake3-aes-128-gcm\r\n",
        "    password: \"AAAAAAAAAAAAAAAAAAAAAA\"\r\n",
        "  - name: \"Unsupported-Hysteria2\"\r\n",
        "    type: hysteria2\r\n",
        "    server: hy2.example.com\r\n",
        "    port: 443\r\n",
        "    password: \"CanarySecretPass_X99!\"\r\n",
        "proxy-groups:\r\n",
        "  - name: \"🚀 Proxy\"\r\n",
        "    type: smart\r\n",
        "    include-all-providers: true\r\n",
        "    exclude-type: \"ss\"\r\n",
        "    interval: \"300s\"\r\n",
        "    tolerance: \"-20\"\r\n",
        "  - name: \"🇯🇵 Japan-Auto\"\r\n",
        "    type: url-test\r\n",
        "    filter: \"(?i)JP|日本\"\r\n",
        "    interval: \"180s\"\r\n",
        "  - name: \"Cycle-A\"\r\n",
        "    type: select\r\n",
        "    proxies: [\"Cycle-B\"]\r\n",
        "  - name: \"Cycle-B\"\r\n",
        "    type: select\r\n",
        "    proxies: [\"Cycle-A\"]\r\n",
        "rule-providers:\r\n",
        "  missing-local:\r\n",
        "    type: file\r\n",
        "    behavior: domain\r\n",
        "    path: ./non-existent-ruleset-for-test.yaml\r\n",
        "  inline-custom:\r\n",
        "    type: inline\r\n",
        "    behavior: classical\r\n",
        "    payload:\r\n",
        "      - DOMAIN-SUFFIX,openai.com\r\n",
        "      - UNSUPPORTED-FUTURE-RULE,foo\r\n",
        "      - IP-CIDR,198.51.100.7\r\n",
        "rules:\r\n",
        "  - RULE-SET,missing-local,REJECT\r\n",
        "  - RULE-SET,inline-custom,🚀 Proxy\r\n",
        "  - NETWORK,udp,REJECT\r\n",
        "  - SRC-PORT,5353,DIRECT\r\n",
        "  - GEOSITE,apple@cn,DIRECT\r\n",
        "  - IP-CIDR,203.0.113.10,DIRECT,no-resolve\r\n",
        "  - FINAL,🚀 Proxy\r\n",
    );

    let (kind, _) = classify_import_input(raw_template).expect("classify wild YAML");
    assert_eq!(kind, ImportInputKind::ClashYaml);

    let (cfg, skipped) = parse_subscription_payload_sanitized(raw_template, &[])
        .map(|(c, _, s)| (c, s))
        .unwrap();
    assert_eq!(cfg.proxies.len(), 3, "expected 3 valid nodes");
    assert_eq!(skipped.len(), 1, "expected 1 skipped hysteria2 node");
    assert_zero_secret_leak(&skipped[0].reason);

    // `mixed-port` == `external-controller` conflict auto-healed without losing mixed-port
    assert_eq!(cfg.mixed_port, 9090);
    assert_eq!(cfg.external_controller, "127.0.0.1:9091");
    cfg.validate()
        .expect("auto-healed config must pass validate()");
    assert_eq!(cfg.bind_address, "::");
    assert_eq!(cfg.dns.fake_ip_range, "198.18.0.1/16");

    // `exclude-type: ss` excluded SG-SS-01 from `🚀 Proxy`, and `type: smart` normalized to `UrlTest`
    let main_grp = cfg
        .proxy_groups
        .iter()
        .find(|g| g.name == "🚀 Proxy")
        .unwrap();
    assert_eq!(main_grp.group_type, ProxyGroupType::UrlTest);
    assert!(main_grp.proxies.iter().any(|m| m.contains("HK-IPLC-01")));
    assert!(main_grp.proxies.iter().any(|m| m.contains("JP-VLESS-01")));
    assert!(!main_grp.proxies.iter().any(|m| m.contains("SG-SS-01")));

    // `filter` without `proxies:` auto-expanded `🇯🇵 Japan-Auto`
    let jp_grp = cfg
        .proxy_groups
        .iter()
        .find(|g| g.name == "🇯🇵 Japan-Auto")
        .unwrap();
    assert_eq!(jp_grp.proxies, vec!["🇯🇵 JP-VLESS-01".to_string()]);

    // Missing `file` rule-provider pruned cleanly, and entire config compiles `Router` + `FakeIpDnsEngine`!
    assert!(!cfg.rule_providers.contains_key("missing-local"));
    assert!(cfg.rule_providers.contains_key("inline-custom"));
    validate_profile_config(&cfg, &[]).expect("router + outbounds + dns must compile cleanly");
}

#[test]
fn wild_legacy_clash_keys_and_final_cascade_rename() {
    let legacy_yaml = r#"
socks-port: 7891
Proxy:
  - { name: "LegacyNode", type: socks5, server: legacy.example.com, port: 1080 }
Proxy Group:
  - { name: "Proxy", type: select, proxies: ["LegacyNode", "DIRECT"] }
Rule:
  - DOMAIN-SUFFIX,example.com,LegacyNode
  - FINAL,LegacyNode
"#;

    let (kind, _) = classify_import_input(legacy_yaml).unwrap();
    assert_eq!(kind, ImportInputKind::ClashYaml);

    let (cfg, _, skipped) = parse_subscription_payload_sanitized(legacy_yaml, &[]).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(cfg.mixed_port, 7891);
    assert_eq!(cfg.proxies.len(), 1);

    let tmp = TempTestDir::new("legacy-rename");
    let mgr = ProfileManager::open_or_init(&tmp.0).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(mgr.import_unified_input(legacy_yaml, None, true, true))
        .unwrap();

    // Rename `LegacyNode` -> `ModernNode` and verify `FINAL,LegacyNode` cascades to `FINAL,ModernNode`!
    let mut renamed = cfg.proxies[0].clone();
    renamed.set_name("ModernNode".to_string());
    let rep = mgr
        .upsert_node_in_active(Some("LegacyNode"), renamed, true)
        .unwrap();
    assert!(
        rep.config.rules.iter().any(|r| r == "FINAL,ModernNode"),
        "FINAL rule target must cascade on node rename: {:?}",
        rep.config.rules
    );
}

#[test]
fn wild_uri_special_passwords_ipv6_roundtrip_and_ultra_long_emoji_names() {
    let long_emoji_name = format!("🇭🇰 专线-IPLC-{}", "極速節點🚀".repeat(28));
    assert!(long_emoji_name.chars().count() > 120);

    // 1. Legacy full-Base64 `ss://` with embedded `?plugin=` and `#fragment`
    let ss_inner = "aes-256-gcm:CanarySecretPass_X99!@ss.example.com:8388?udp=1#LegacySSFrag";
    let ss_b64 = format!("ss://{}", STANDARD.encode(ss_inner));
    let parsed_ss = parse_proxy_uri(&ss_b64).expect("legacy ss b64 with query+frag");
    assert_eq!(parsed_ss.name(), "LegacySSFrag");

    // 2. Trojan & AnyTLS with raw unencoded `:` and `@` in passwords + IPv6 host
    let trojan_raw = "\u{feff}trojan://p@ss:w0rd:with@at@[2001:db8::abcd]:8443?sni=ipv6.example.com#TrojanIPv6\r\n";
    let parsed_trojan = parse_proxy_uri(trojan_raw).expect("trojan raw @/: password + IPv6");
    let exported_trojan = export_proxy_uri(&parsed_trojan);
    assert!(
        exported_trojan.contains("[2001:db8::abcd]:8443"),
        "IPv6 export must bracket host: {exported_trojan}"
    );
    let reparsed_trojan = parse_proxy_uri(&exported_trojan).expect("reparse exported IPv6 trojan");
    assert_eq!(reparsed_trojan.server_port(), ("2001:db8::abcd", 8443));

    let encoded_name: String = long_emoji_name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let anytls_raw =
        format!("anytls://sec@ret:key!@[2001:db8::99]:443?sni=any.example.com#{encoded_name}");
    let parsed_anytls = parse_proxy_uri(&anytls_raw).expect("anytls raw @/: password + 120+ emoji");
    assert_eq!(parsed_anytls.name(), long_emoji_name);
    let exported_anytls = export_proxy_uri(&parsed_anytls);
    let reparsed_anytls = parse_proxy_uri(&exported_anytls).expect("reparse exported anytls");
    assert_eq!(reparsed_anytls.name(), long_emoji_name);
    assert_eq!(reparsed_anytls.server_port().0, "2001:db8::99");

    // 3. VLESS with `tls=1&skip-cert-verify=1&fp=chrome&pbk=ignored` succeeds while `security=reality` skips cleanly
    let mixed_uris = format!(
        "vless://{CANARY_UUID}@vless.example.com:443?tls=1&skip-cert-verify=1&fp=chrome&sni=vless.example.com#VLESS-OK\n\
         vless://{CANARY_UUID}@reality.example.com:443?security=reality&pbk=secret_pub_key#VLESS-REALITY\n\
         vmess://eyJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSJ9"
    );
    let (nodes, skipped) = parse_subscription_uris_best_effort(&mixed_uris).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name(), "VLESS-OK");
    assert_eq!(skipped.len(), 2);
    for s in &skipped {
        assert_zero_secret_leak(&s.reason);
    }
}

#[test]
fn wild_html_cloudflare_and_json_panel_error_diagnostics_redact_secrets() {
    // 1. Cloudflare 5xx / challenge HTML page
    let cf_html = r#"<!DOCTYPE html>
<html lang="en-US"><head><title>Attention Required! | Cloudflare</title></head>
<body><div data-cf-ray="8abc12345">Checking your browser</div></body></html>"#;
    let err_cf = classify_import_input(cf_html).unwrap_err().to_string();
    assert!(
        err_cf.contains("Cloudflare"),
        "expected Cloudflare diagnostic, got: {err_cf}"
    );

    // 2. Generic HTML login / captive portal page
    let portal_html = "<html><head><title>Sign In</title></head><body>Please login</body></html>";
    let err_html = classify_import_input(portal_html).unwrap_err().to_string();
    assert!(
        err_html.contains("HTML webpage"),
        "expected HTML webpage diagnostic, got: {err_html}"
    );

    // 3. V2Board / Xboard JSON error containing leaked token
    let v2board_json = format!(
        r#"{{"status":"error","message":"token is error: token={CANARY_TOKEN} uuid={CANARY_UUID}"}}"#
    );
    let err_v2b = classify_import_input(&v2board_json)
        .unwrap_err()
        .to_string();
    assert!(
        err_v2b.contains("subscription panel returned an error"),
        "got: {err_v2b}"
    );
    assert_zero_secret_leak(&err_v2b);

    // 4. Base64-encoded SSPanel `{"ret":0,"msg":"..."}` error
    let sspanel_b64 = STANDARD.encode(format!(
        r#"{{"ret":0,"msg":"订阅已过期 password={CANARY_PASS}"}}"#
    ));
    let err_ssp = classify_import_input(&sspanel_b64).unwrap_err().to_string();
    assert!(
        err_ssp.contains("subscription panel returned an error"),
        "got: {err_ssp}"
    );
    assert_zero_secret_leak(&err_ssp);

    // 5. Sing-box JSON config
    let singbox_json = r#"{"inbounds":[{"type":"tun"}],"outbounds":[{"type":"vless"}],"route":{}}"#;
    let err_sb = classify_import_input(singbox_json).unwrap_err().to_string();
    assert!(
        err_sb.contains("Sing-box"),
        "expected Sing-box diagnostic, got: {err_sb}"
    );
}

#[tokio::test]
async fn wild_http_subscription_gzip_user_agent_non2xx_and_bomb_defense() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                // Verify User-Agent advertises Clash.Meta / mihomo so V2Board/Subconverter serve modern nodes
                let has_mihomo_ua = req.lines().any(|l| {
                    l.to_ascii_lowercase().starts_with("user-agent:") && l.contains("Clash.Meta")
                });
                assert!(
                    has_mihomo_ua,
                    "missing Clash.Meta User-Agent in request: {req}"
                );

                match path {
                    "/gzip-sub" => {
                        let yaml = "proxies:\n  - { name: GzipNode, type: socks5, server: gz.example.com, port: 1080 }\n";
                        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
                        enc.write_all(yaml.as_bytes()).unwrap();
                        let gz_bytes = enc.finish().unwrap();
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nSubscription-Userinfo: upload=1024; download=2048; total=999999\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            gz_bytes.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&gz_bytes).await;
                    }
                    "/forbidden-json" => {
                        let body = format!(
                            r#"{{"status":"error","message":"invalid token={CANARY_TOKEN}"}}"#
                        );
                        let resp = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    }
                    "/empty-200" => {
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\xef\xbb\xbf\r\n")
                            .await;
                    }
                    "/gzip-bomb" => {
                        // 10 MiB of zeros compresses to ~10 KiB over the wire, exceeding the 8 MiB decompressed cap!
                        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
                        let chunk = vec![b'A'; 64 * 1024];
                        for _ in 0..160 {
                            enc.write_all(&chunk).unwrap();
                        }
                        let gz_bytes = enc.finish().unwrap();
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            gz_bytes.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&gz_bytes).await;
                    }
                    _ => {}
                }
                let _ = sock.shutdown().await;
            });
        }
    });

    // 1. Gzip subscription succeeds and parses Subscription-Userinfo
    let (body, uinfo) = fetch_subscription_http(&format!("http://{addr}/gzip-sub"), &[])
        .await
        .expect("gzip subscription fetch");
    let (cfg, _, _) = parse_subscription_payload_sanitized(&body, &[]).unwrap();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name(), "GzipNode");
    assert_eq!(uinfo.unwrap().download_bytes, 2048);

    // 2. HTTP 403 JSON panel error extracts & redacts message
    let err_403 = fetch_subscription_http(&format!("http://{addr}/forbidden-json"), &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err_403.contains("HTTP 403"), "got: {err_403}");
    assert_zero_secret_leak(&redact_sensitive_text(&err_403));

    // 3. HTTP 200 empty body surfaces clear error
    let err_empty = fetch_subscription_http(&format!("http://{addr}/empty-200"), &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err_empty.contains("empty response body"),
        "got: {err_empty}"
    );

    // 4. Gzip bomb (> 8 MiB decompressed) is bounded & rejected safely
    let err_bomb = fetch_subscription_http(&format!("http://{addr}/gzip-bomb"), &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err_bomb.contains("8 MiB"), "got: {err_bomb}");
}

// ============================================================================
// Property-Based Fuzzing (`3 * 400 = 1,200` generated inputs):
// Prove zero panics AND zero secret/UUID/token leaks across arbitrary mutations!
// ============================================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn fuzz_yaml_subscriptions_never_panic_or_leak_secrets(
        prefix in "[\u{feff}\0 \r\n-]{0,6}",
        arbitrary_body in "\\PC{0,320}",
        proto in prop_oneof![
            Just("ss"),
            Just("vless"),
            Just("trojan"),
            Just("anytls"),
            Just("socks5"),
            Just("http"),
            Just("vmess"),
            Just("hysteria2"),
            Just("tuic"),
        ],
        port_raw in prop_oneof![
            Just("443".to_string()),
            Just("0".to_string()),
            Just("99999".to_string()),
            Just("\"not-a-port\"".to_string()),
            Just("-1".to_string()),
        ],
        inject_anchor_loop in any::<bool>(),
    ) {
        let anchor_snippet = if inject_anchor_loop {
            "a: &a\n  b: 1\nc: &b\n  <<: *a\n"
        } else {
            ""
        };
        let mutated_yaml = format!(
            "{prefix}{anchor_snippet}proxies:\n  - name: \"FuzzNode\"\n    type: {proto}\n    server: fuzz.example.com\n    port: {port_raw}\n    uuid: {CANARY_UUID}\n    password: \"{CANARY_PASS}\"\n    token: \"{CANARY_TOKEN}\"\n{arbitrary_body}"
        );

        if let Err(e) = ClashConfig::from_yaml_str(&mutated_yaml) {
            let safe = redact_sensitive_text(&e.to_string());
            assert_zero_secret_leak(&safe);
        }
        if let Err(e) = ClashConfig::from_yaml_str_sanitized(&mutated_yaml) {
            let safe = redact_sensitive_text(&e.to_string());
            assert_zero_secret_leak(&safe);
        }
        if let Err(e) = parse_subscription_payload_sanitized(&mutated_yaml, &[]) {
            let safe = redact_sensitive_text(&e.to_string());
            assert_zero_secret_leak(&safe);
        }
    }

    #[test]
    fn fuzz_uri_and_classifier_inputs_never_panic_or_leak_secrets(
        scheme in prop_oneof![
            Just("ss://"),
            Just("vless://"),
            Just("trojan://"),
            Just("anytls://"),
            Just("socks5://"),
            Just("http://"),
            Just("https://"),
            Just("clash://install-config?url="),
            Just("vmess://"),
            Just("ssr://"),
            Just(""),
        ],
        noise in "[a-zA-Z0-9:@/?#=&_%\\[\\].+=-]{0,180}",
        wrap_base64 in any::<bool>(),
    ) {
        let raw_candidate = format!(
            "{scheme}{CANARY_UUID}:{CANARY_PASS}@sub.example.com:443/?token={CANARY_TOKEN}&{noise}#Node"
        );
        let input = if wrap_base64 {
            STANDARD.encode(&raw_candidate)
        } else {
            raw_candidate
        };

        match classify_import_input(&input) {
            Ok(_) => {}
            Err(e) => {
                let safe = redact_sensitive_text(&e.to_string());
                assert_zero_secret_leak(&safe);
            }
        }
        if let Err(e) = parse_proxy_uri(&input) {
            let safe = redact_sensitive_text(&e.to_string());
            assert_zero_secret_leak(&safe);
        }
        match parse_subscription_uris_best_effort(&input) {
            Ok((_, skipped)) => {
                for s in skipped {
                    assert_zero_secret_leak(&s.reason);
                }
            }
            Err(e) => {
                let safe = redact_sensitive_text(&e.to_string());
                assert_zero_secret_leak(&safe);
            }
        }
    }

    #[test]
    fn fuzz_valid_proxy_uri_export_and_parse_roundtrip(
        host_choice in prop_oneof![
            Just("edge.example.com".to_string()),
            Just("198.51.100.42".to_string()),
            Just("2001:db8::42".to_string()),
        ],
        port in 1u16..=65535u16,
        pass in "[a-zA-Z0-9!@$%^&*:_.-]{6,32}",
        name in "[A-Za-z0-9_🚀🇭🇰🇯🇵 -]{1,64}",
        proto_idx in 0u8..4u8,
    ) {
        let clean_name = name.trim();
        let effective_name = if clean_name.is_empty() { "Node" } else { clean_name };
        let yaml_node = match proto_idx {
            0 => serde_json::json!({
                "name": effective_name,
                "type": "ss",
                "server": host_choice,
                "port": port,
                "cipher": "aes-256-gcm",
                "password": pass,
                "udp": true,
            }),
            1 => serde_json::json!({
                "name": effective_name,
                "type": "trojan",
                "server": host_choice,
                "port": port,
                "password": pass,
                "sni": "edge.example.com",
                "skip-cert-verify": false,
                "udp": true,
            }),
            2 => serde_json::json!({
                "name": effective_name,
                "type": "anytls",
                "server": host_choice,
                "port": port,
                "password": pass,
                "sni": "edge.example.com",
                "skip-cert-verify": false,
                "udp": true,
            }),
            _ => serde_json::json!({
                "name": effective_name,
                "type": "vless",
                "server": host_choice,
                "port": port,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "tls": true,
                "servername": "edge.example.com",
                "udp": true,
            }),
        };

        let node: ProxyNodeConfig = serde_json::from_value(yaml_node).unwrap();
        let uri = export_proxy_uri(&node);
        let reparsed = parse_proxy_uri(&uri).unwrap_or_else(|e| {
            panic!("failed to reparse exported URI `{uri}`: {e}");
        });
        prop_assert_eq!(reparsed.server_port(), (host_choice.as_str(), port));
        prop_assert_eq!(reparsed.name(), effective_name);
    }
}

#[test]
fn yaml_alias_bomb_billion_laughs_is_rejected_safely_without_oom_or_secret_leak() {
    let bomb = format!(
        concat!(
            "secret-canary: \"{pass}\"\n",
            "uuid-canary: \"{uuid}\"\n",
            "token-canary: \"{tok}\"\n",
            "a0: &a0 [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n",
            "a1: &a1 [*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0]\n",
            "a2: &a2 [*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1]\n",
            "a3: &a3 [*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2]\n",
            "a4: &a4 [*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3]\n",
            "a5: &a5 [*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4]\n",
            "a6: &a6 [*a5,*a5,*a5,*a5,*a5,*a5,*a5,*a5,*a5,*a5]\n",
            "a7: &a7 [*a6,*a6,*a6,*a6,*a6,*a6,*a6,*a6,*a6,*a6]\n",
            "proxies:\n",
            "  - name: \"Node1\"\n",
            "    type: trojan\n",
            "    server: edge.example.com\n",
            "    port: 443\n",
            "    password: \"{pass}\"\n"
        ),
        pass = CANARY_PASS,
        uuid = CANARY_UUID,
        tok = CANARY_TOKEN,
    );

    let start = std::time::Instant::now();
    let err1 = ClashConfig::from_yaml_str(&bomb).expect_err("alias bomb must be rejected");
    assert_zero_secret_leak(&err1.to_string());

    let err2 =
        ClashConfig::from_yaml_str_sanitized(&bomb).expect_err("alias bomb must be rejected");
    assert_zero_secret_leak(&err2.to_string());
    assert!(
        start.elapsed().as_secs() < 5,
        "alias bomb rejection took too long: {:?}",
        start.elapsed()
    );
}

#[test]
fn yaml_saphyr_wild_edge_cases_duplicate_keys_str_tags_yaml12_booleans_and_roundtrip() {
    // Covers:
    // 1. Duplicate YAML mapping keys (`LastWins`)
    // 2. Subconverter `!<str> 00123456` and unquoted `00987654` leading-zero numeric passwords
    // 3. Unquoted `NO` (Norway country code) preserved as `"NO"` via YAML 1.2 strict booleans,
    //    while `tls: yes` and `udp: on` still coerce to `true`
    // 4. Null (`~`) and integer (`123`) keys in mappings skipped/converted cleanly
    // 5. 200+ proxy nodes reusing a single `&shared_tls` anchor without tripping alias-ratio false positives
    // 6. `ClashConfig::to_yaml_string()` -> `ClashConfig::from_yaml_str()` round-trip
    let mut yaml = String::from(concat!(
        "mixed-port: 7890\n",
        "mixed-port: 7892\n",
        "~: ignored_null_key\n",
        "123: ignored_numeric_root_key\n",
        "shared-tls: &shared_tls\n",
        "  sni: cdn.example.com\n",
        "  skip-cert-verify: off\n",
        "proxies:\n",
        "  - name: NO\n",
        "    type: ss\n",
        "    server: no-edge.example.com\n",
        "    port: 8388\n",
        "    cipher: aes-256-gcm\n",
        "    password: !<str> 00123456\n",
        "    udp: false\n",
        "    udp: on\n",
        "  - name: LeadingZeroPass\n",
        "    type: trojan\n",
        "    server: trojan.example.com\n",
        "    port: 443\n",
        "    password: 00987654\n",
        "    <<: *shared_tls\n",
        "  - name: VlessYesTls\n",
        "    type: vless\n",
        "    server: vless.example.com\n",
        "    port: 443\n",
        "    uuid: 11111111-2222-3333-4444-555555555555\n",
        "    tls: yes\n",
        "    <<: *shared_tls\n",
    ));

    for i in 0..200 {
        yaml.push_str(&format!(
            "  - name: BulkNode-{i}\n    type: trojan\n    server: bulk-{i}.example.com\n    port: 443\n    password: pass-{i}-secret\n    <<: *shared_tls\n"
        ));
    }

    yaml.push_str(concat!(
        "proxy-groups:\n",
        "  - name: PROXY\n",
        "    type: select\n",
        "    include-all: true\n",
        "rules:\n",
        "  - MATCH,PROXY\n",
    ));

    let (cfg, skipped) = ClashConfig::from_yaml_str_sanitized(&yaml)
        .expect("wild edge-case YAML must parse cleanly");
    assert!(
        skipped.is_empty(),
        "unexpected skipped entries: {skipped:?}"
    );
    assert_eq!(cfg.mixed_port, 7892);
    assert_eq!(cfg.proxies.len(), 203);
    assert_eq!(cfg.proxies[0].name(), "NO");

    match &cfg.proxies[0] {
        ProxyNodeConfig::Ss { password, udp, .. } => {
            assert_eq!(password, "00123456");
            assert!(*udp);
        }
        other => panic!("expected Shadowsocks node, got {other:?}"),
    }
    match &cfg.proxies[1] {
        ProxyNodeConfig::Trojan {
            password,
            sni,
            skip_cert_verify,
            ..
        } => {
            assert_eq!(password, "00987654");
            assert_eq!(sni.as_deref(), Some("cdn.example.com"));
            assert!(!*skip_cert_verify);
        }
        other => panic!("expected Trojan node, got {other:?}"),
    }
    match &cfg.proxies[2] {
        ProxyNodeConfig::Vless {
            tls, servername, ..
        } => {
            assert!(*tls);
            assert_eq!(servername.as_deref(), Some("cdn.example.com"));
        }
        other => panic!("expected VLESS node, got {other:?}"),
    }

    let serialized = cfg.to_yaml_string().expect("to_yaml_string must succeed");
    let reparsed =
        ClashConfig::from_yaml_str(&serialized).expect("round-tripped YAML must parse cleanly");
    assert_eq!(reparsed.mixed_port, 7892);
    assert_eq!(reparsed.proxies.len(), 203);
    assert_eq!(reparsed.proxies[0].name(), "NO");
}
