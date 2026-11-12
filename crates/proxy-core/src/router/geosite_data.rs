use std::{collections::HashSet, sync::LazyLock};

/// Compiled `GEOSITE` category matcher using O(1) exact hash + O(labels) suffix walk + keyword list.
/// Supports both zero-network built-in baseline datasets and dynamically updated persistent GeoSite lists.
#[derive(Clone, Debug, Default)]
pub struct GeoSiteMatcher {
    exact: HashSet<String>,
    suffixes: HashSet<String>,
    keywords: Vec<String>,
}

impl GeoSiteMatcher {
    pub fn from_lists(exact_list: &[&str], suffix_list: &[&str], keyword_list: &[&str]) -> Self {
        Self {
            exact: exact_list
                .iter()
                .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            suffixes: suffix_list
                .iter()
                .map(|s| {
                    s.trim()
                        .trim_start_matches("+.")
                        .trim_start_matches('.')
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                })
                .filter(|s| !s.is_empty())
                .collect(),
            keywords: keyword_list
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// Parse Clash / MetaCubeX / Loyalsoldier domain or classical rule-set text (plain lines or YAML `payload:`)
    /// into a `GeoSiteMatcher`.
    ///
    /// Supported line syntaxes:
    /// - `+.example.com` or `.example.com` (domain suffix)
    /// - `DOMAIN-SUFFIX,example.com` (domain suffix)
    /// - `DOMAIN,exact.example.com` or `full:exact.example.com` (exact domain)
    /// - `DOMAIN-KEYWORD,google` or `keyword:google` (keyword)
    /// - `example.com` (treated as domain suffix in standard GeoSite / Clash domain lists)
    pub fn from_rule_text(text: &str) -> Self {
        let mut exact = HashSet::new();
        let mut suffixes = HashSet::new();
        let mut keywords = Vec::new();
        let mut keyword_seen = HashSet::new();

        for raw_line in text.lines() {
            let mut line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.eq_ignore_ascii_case("payload:") {
                continue;
            }
            if let Some(rest) = line.strip_prefix('-') {
                line = rest.trim();
            }
            line = line.trim_matches('\'').trim_matches('"').trim();
            if let Some((before_comment, _)) = line.split_once(" #") {
                line = before_comment.trim();
            }
            if line.is_empty() {
                continue;
            }

            if let Some((kind_raw, rest)) = line.split_once(',') {
                let kind = kind_raw.trim().to_ascii_uppercase();
                let val = rest
                    .split(',')
                    .next()
                    .unwrap_or(rest)
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if val.is_empty() {
                    continue;
                }
                match kind.as_str() {
                    "DOMAIN" => {
                        exact.insert(val);
                    }
                    "DOMAIN-SUFFIX" => {
                        let clean = val.trim_start_matches("+.").trim_start_matches('.');
                        if !clean.is_empty() {
                            suffixes.insert(clean.to_string());
                        }
                    }
                    "DOMAIN-KEYWORD" if keyword_seen.insert(val.clone()) => {
                        keywords.push(val);
                    }
                    _ => {}
                }
                continue;
            }

            if let Some(full_dom) = line.strip_prefix("full:") {
                let d = strip_geosite_line_attrs(full_dom)
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if is_plausible_domain_token(&d) {
                    exact.insert(d);
                }
                continue;
            }
            if let Some(kw) = line.strip_prefix("keyword:") {
                let k = strip_geosite_line_attrs(kw).to_ascii_lowercase();
                if !k.is_empty() && keyword_seen.insert(k.clone()) {
                    keywords.push(k);
                }
                continue;
            }
            let raw_no_prefix = line.strip_prefix("domain:").unwrap_or(line);
            let domain_raw = strip_geosite_line_attrs(raw_no_prefix)
                .trim_start_matches("+.")
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();

            if is_plausible_domain_token(&domain_raw) {
                suffixes.insert(domain_raw);
            }
        }

        Self {
            exact,
            suffixes,
            keywords,
        }
    }

    pub fn merged_with(&self, extra: &GeoSiteMatcher) -> Self {
        let mut exact = self.exact.clone();
        exact.extend(extra.exact.iter().cloned());

        let mut suffixes = self.suffixes.clone();
        suffixes.extend(extra.suffixes.iter().cloned());

        let mut keywords = self.keywords.clone();
        for kw in &extra.keywords {
            if !keywords.contains(kw) {
                keywords.push(kw.clone());
            }
        }
        Self {
            exact,
            suffixes,
            keywords,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.exact.len() + self.suffixes.len() + self.keywords.len()
    }

    pub fn matches_domain(&self, raw_domain: &str) -> bool {
        let domain = raw_domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }
        if self.exact.contains(domain.as_str()) {
            return true;
        }
        // O(labels) suffix walk: `api.sub.example.com` -> `api.sub.example.com`, `sub.example.com`, `example.com`, `com`
        let mut cursor = domain.as_str();
        loop {
            if self.suffixes.contains(cursor) {
                return true;
            }
            match cursor.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => cursor = rest,
                _ => break,
            }
        }
        self.keywords.iter().any(|kw| domain.contains(kw.as_str()))
    }
}

fn strip_geosite_line_attrs(s: &str) -> &str {
    let trimmed = s.trim();
    let without_colon_attr = trimmed
        .split_once(":@")
        .map_or(trimmed, |(before, _)| before);
    let without_space_attr = without_colon_attr
        .split_whitespace()
        .next()
        .unwrap_or(without_colon_attr);
    without_space_attr
        .split_once('@')
        .map_or(without_space_attr, |(before, _)| before)
        .trim()
}

fn is_plausible_domain_token(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.contains('/') || s.contains(':') || s.contains(' ') {
        return false;
    }
    // Reject HTML tags or captive portal lines (`<html>`, etc.)
    if s.contains('<') || s.contains('>') {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoSiteAttrFilter {
    pub negated: bool,
    pub name: String,
}

/// Parse `GEOSITE` category expression such as `google@cn` or `apple@!cn` into
/// `(normalized_base, Vec<GeoSiteAttrFilter>)`.
pub fn parse_geosite_category_and_attrs(category: &str) -> (String, Vec<GeoSiteAttrFilter>) {
    let mut parts = category.trim().split('@');
    let base = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let mut attrs = Vec::new();
    for raw_attr in parts {
        let t = raw_attr.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(neg) = t.strip_prefix('!') {
            let clean = neg.trim().to_ascii_lowercase();
            if !clean.is_empty() {
                attrs.push(GeoSiteAttrFilter {
                    negated: true,
                    name: clean,
                });
            }
        } else {
            attrs.push(GeoSiteAttrFilter {
                negated: false,
                name: t.to_ascii_lowercase(),
            });
        }
    }
    (base, attrs)
}

pub fn normalize_geosite_category(category: &str) -> String {
    parse_geosite_category_and_attrs(category).0
}

pub fn lookup_builtin_geosite(category: &str) -> Option<&'static GeoSiteMatcher> {
    let base = normalize_geosite_category(category);
    match base.as_str() {
        "private" | "lan" => Some(&GEOSITE_PRIVATE),
        "cn" | "china" | "geolocation-cn" => Some(&GEOSITE_CN),
        "geolocation-!cn" | "gfw" | "proxy" | "tld-!cn" => Some(&GEOSITE_NON_CN),
        "google" | "google-cn" => Some(&GEOSITE_GOOGLE),
        "youtube" => Some(&GEOSITE_YOUTUBE),
        "github" => Some(&GEOSITE_GITHUB),
        "openai" | "chatgpt" => Some(&GEOSITE_OPENAI),
        "anthropic" | "claude" => Some(&GEOSITE_ANTHROPIC),
        "netflix" => Some(&GEOSITE_NETFLIX),
        "telegram" => Some(&GEOSITE_TELEGRAM),
        "twitter" | "x" => Some(&GEOSITE_TWITTER),
        "apple" | "icloud" | "apple-cn" => Some(&GEOSITE_APPLE),
        "microsoft" | "bing" | "microsoft-cn" => Some(&GEOSITE_MICROSOFT),
        "cloudflare" => Some(&GEOSITE_CLOUDFLARE),
        "steam" | "steam-cn" => Some(&GEOSITE_STEAM),
        "discord" => Some(&GEOSITE_DISCORD),
        "spotify" => Some(&GEOSITE_SPOTIFY),
        "category-ads" | "category-ads-all" | "ads" => Some(&GEOSITE_ADS),
        _ => None,
    }
}

/// Built-in `@cn` domestic CDN/direct subsets for multi-region international categories.
pub fn lookup_builtin_geosite_cn_subset(base: &str) -> Option<&'static GeoSiteMatcher> {
    match base {
        "google" | "google-cn" => Some(&GEOSITE_GOOGLE_CN),
        "apple" | "icloud" | "apple-cn" => Some(&GEOSITE_APPLE_CN),
        "microsoft" | "bing" | "microsoft-cn" => Some(&GEOSITE_MICROSOFT_CN),
        "steam" | "steam-cn" => Some(&GEOSITE_STEAM_CN),
        _ => None,
    }
}

static GEOSITE_PRIVATE: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[
            "localhost",
            "ip6-localhost",
            "ip6-loopback",
            "captive.apple.com",
            "connectivitycheck.platform.hicloud.com",
            "wifi.vivo.com.cn",
            "connect.rom.miui.com",
        ],
        &[
            "local",
            "lan",
            "internal",
            "home.arpa",
            "intranet",
            "corp",
            "localdomain",
            "test",
            "invalid",
            "msftconnecttest.com",
            "msftncsi.com",
        ],
        &[],
    )
});

static GEOSITE_CN: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            // Country & Chinese IDN TLDs
            "cn",
            "xn--fiqs8s",
            "xn--fiqz9s",
            "xn--zfr164b",
            "xn--55qx5d",
            "xn--io0a7i",
            // Search, Portals & Domestic AI
            "baidu.com",
            "bdstatic.com",
            "bdimg.com",
            "baidubce.com",
            "bcebos.com",
            "baiducontent.com",
            "shifen.com",
            "hao123.com",
            "sogou.com",
            "sogo.com",
            "sogoucdn.com",
            "so.com",
            "360.cn",
            "360safe.com",
            "qhimg.com",
            "qhres.com",
            "deepseek.com",
            "moonshot.cn",
            "kimi.ai",
            "doubao.com",
            "zhipuai.cn",
            "chatglm.cn",
            "baichuan-ai.com",
            "minimax.io",
            // Tencent / WeChat / QQ / QCloud
            "qq.com",
            "weixin.qq.com",
            "wechat.com",
            "servicewechat.com",
            "wx.qq.com",
            "tenpay.com",
            "gtimg.com",
            "gtimg.cn",
            "qpic.cn",
            "qlogo.cn",
            "idqqimg.com",
            "myapp.com",
            "myqcloud.com",
            "tencent.com",
            "tencent-cloud.net",
            "tencent-cloud.com",
            "tencentcloud.com",
            "qcloud.com",
            "qcloudimg.com",
            "dnspod.cn",
            "doh.pub",
            "smtcdns.net",
            "weiyun.com",
            // Alibaba / Taobao / Tmall / Alipay / Aliyun
            "alibaba.com",
            "alibabacloud.com",
            "aliyun.com",
            "aliyuncs.com",
            "aliyuncdn.com",
            "alikunlun.com",
            "alidns.com",
            "taobao.com",
            "tmall.com",
            "tmall.hk",
            "tbcdn.cn",
            "alicdn.com",
            "mmstat.com",
            "tanx.com",
            "alipay.com",
            "alipayobjects.com",
            "1688.com",
            "cainiao.com",
            "ele.me",
            "elemecdn.com",
            "fliggy.com",
            "goofish.com",
            "dingtalk.com",
            "uc.cn",
            "ucweb.com",
            // Bilibili & Video / Streaming / Live / Music
            "bilibili.com",
            "bilivideo.com",
            "bilivideo.cn",
            "hdslb.com",
            "biliapi.net",
            "biliapi.com",
            "b23.tv",
            "acgvideo.com",
            "biligame.com",
            "iqiyi.com",
            "iqiyipic.com",
            "qiyi.com",
            "71.am",
            "youku.com",
            "ykimg.com",
            "tudou.com",
            "mgtv.com",
            "imgo.tv",
            "hunantv.com",
            "le.com",
            "letv.com",
            "pptv.com",
            "acfun.cn",
            "aixifan.com",
            "douyu.com",
            "douyucdn.cn",
            "huya.com",
            "msstatic.com",
            "kuaishou.com",
            "gifshow.com",
            "yximgs.com",
            "kwai.net",
            "cctv.com",
            "cctvpic.com",
            "cntv.cn",
            "kugou.com",
            "kuwo.cn",
            "migu.cn",
            "miguvideo.com",
            "ximalaya.com",
            "xmcdn.com",
            // ByteDance / Douyin / Toutiao / Feishu / Volcano Engine
            "bytedance.com",
            "douyin.com",
            "douyincdn.com",
            "douyinpic.com",
            "douyinvod.com",
            "iesdouyin.com",
            "toutiao.com",
            "toutiaoimg.com",
            "ixigua.com",
            "snssdk.com",
            "pstatp.com",
            "byteimg.com",
            "bytescm.com",
            "bytetos.com",
            "bytegoofy.com",
            "zijieapi.com",
            "volces.com",
            "volccdn.com",
            "volcengine.com",
            "feishu.cn",
            "feishucdn.com",
            // E-Commerce, Local Life, Delivery & Travel
            "jd.com",
            "jd.hk",
            "360buy.com",
            "360buyimg.com",
            "jcloudcs.com",
            "pinduoduo.com",
            "yangkeduo.com",
            "pddpic.com",
            "pddugc.com",
            "meituan.com",
            "meituan.net",
            "sankuai.com",
            "dianping.com",
            "dpfile.com",
            "vip.com",
            "appsimg.com",
            "suning.com",
            "dangdang.com",
            "smzdm.com",
            "zdmimg.com",
            "dewu.com",
            "poizon.com",
            "didiglobal.com",
            "didistatic.com",
            "udache.com",
            "ctrip.com",
            "c-ctrip.com",
            "qunar.com",
            "qunarzz.com",
            "ly.com",
            "12306.cn",
            "amap.com",
            "autonavi.com",
            "sf-express.com",
            "kuaidi100.com",
            // Social, Communities, News & Developer Portals CN
            "xiaohongshu.com",
            "xhscdn.com",
            "xhscdn.net",
            "xhslink.com",
            "weibo.com",
            "weibocdn.com",
            "sina.com",
            "sina.com.cn",
            "sinaimg.cn",
            "sinajs.cn",
            "zhihu.com",
            "zhimg.com",
            "douban.com",
            "doubanio.com",
            "hupu.com",
            "nga.cn",
            "ngabbs.com",
            "163.com",
            "126.com",
            "126.net",
            "127.net",
            "yeah.net",
            "netease.com",
            "163yun.com",
            "youdao.com",
            "ydstatic.com",
            "sohu.com",
            "sohucs.com",
            "itc.cn",
            "ifeng.com",
            "ifengimg.com",
            "eastmoney.com",
            "xueqiu.com",
            "36kr.com",
            "huxiu.com",
            "sspai.com",
            "ithome.com",
            "ruanmei.com",
            "csdn.net",
            "csdnimg.cn",
            "juejin.cn",
            "byteacct.com",
            "gitee.com",
            "oschina.net",
            "cnblogs.com",
            "segmentfault.com",
            "nowcoder.com",
            "leetcode.cn",
            // Hardware, Mobile Ecosystems, Office & Banking CN
            "xiaomi.com",
            "xiaomi.net",
            "mi.com",
            "miui.com",
            "mifile.cn",
            "huawei.com",
            "vmall.com",
            "hicloud.com",
            "dbankcdn.com",
            "harmonyos.com",
            "hihonor.com",
            "honor.com",
            "oppo.com",
            "oppomobile.com",
            "heytap.com",
            "heytapimage.com",
            "coloros.com",
            "vivo.com",
            "iqoo.com",
            "oneplus.com",
            "meizu.com",
            "flyme.cn",
            "lenovo.com",
            "dji.com",
            "wps.cn",
            "wpscdn.cn",
            "kdocs.cn",
            "unionpay.com",
            "95516.com",
            "cmbchina.com",
            "ccb.com",
            "abchina.com",
            "pingan.com",
            // Gaming & Domestic App/Game CDNs
            "mihoyo.com",
            "miyoushe.com",
            "hypergryph.com",
            "tapimg.com",
            "taptap.cn",
            "wanmei.com",
            "wmsjsteam.com",
            "steamcontent.com",
            "dl.steam.clngaa.com",
            "st.dl.eccdnx.com",
            "apple.com.cn",
            "icloud.com.cn",
        ],
        &[],
    )
});

static GEOSITE_NON_CN: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            // Google & YouTube
            "google.com",
            "google.co.jp",
            "google.co.uk",
            "google.com.hk",
            "google.com.sg",
            "google.com.tw",
            "google.de",
            "googleapis.com",
            "gstatic.com",
            "googleusercontent.com",
            "ggpht.com",
            "gvt1.com",
            "gvt2.com",
            "1e100.net",
            "gmail.com",
            "android.com",
            "chromium.org",
            "golang.org",
            "go.dev",
            "youtube.com",
            "youtu.be",
            "ytimg.com",
            "googlevideo.com",
            "youtube-nocookie.com",
            // Developer, Cloud & AI International
            "github.com",
            "github.io",
            "githubusercontent.com",
            "githubassets.com",
            "ghcr.io",
            "githubcopilot.com",
            "gitlab.com",
            "bitbucket.org",
            "stackoverflow.com",
            "stackexchange.com",
            "sstatic.net",
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "sora.com",
            "anthropic.com",
            "claude.ai",
            "claudeusercontent.com",
            "perplexity.ai",
            "huggingface.co",
            "hf.co",
            "cohere.com",
            "mistral.ai",
            "x.ai",
            "grok.com",
            "docker.com",
            "docker.io",
            "crates.io",
            "rust-lang.org",
            "npmjs.org",
            "npmjs.com",
            "pypi.org",
            "pythonhosted.org",
            "vercel.app",
            "vercel.com",
            "netlify.app",
            "pages.dev",
            "workers.dev",
            "cloudflare-dns.com",
            "one.one.one.one",
            "dns.google",
            // Social, Messaging & Knowledge International
            "wikipedia.org",
            "wikimedia.org",
            "wiktionary.org",
            "wikidata.org",
            "archive.org",
            "reddit.com",
            "redd.it",
            "redditmedia.com",
            "redditstatic.com",
            "twitter.com",
            "x.com",
            "twimg.com",
            "t.co",
            "facebook.com",
            "fb.com",
            "fbcdn.net",
            "instagram.com",
            "cdninstagram.com",
            "threads.net",
            "whatsapp.com",
            "whatsapp.net",
            "messenger.com",
            "telegram.org",
            "telegram.me",
            "t.me",
            "tdesktop.com",
            "telegra.ph",
            "signal.org",
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "line.me",
            "kakao.com",
            "quora.com",
            "medium.com",
            "substack.com",
            "v2ex.com",
            "pinterest.com",
            "pinimg.com",
            "tumblr.com",
            "pixiv.net",
            "pximg.net",
            // Media, Video, Music, News & Gaming International
            "netflix.com",
            "netflix.net",
            "nflxext.com",
            "nflximg.net",
            "nflxso.net",
            "nflxvideo.net",
            "spotify.com",
            "scdn.co",
            "spotifycdn.com",
            "twitch.tv",
            "ttvnw.net",
            "jtvnw.net",
            "tiktok.com",
            "tiktokv.com",
            "tiktokcdn.com",
            "vimeo.com",
            "dailymotion.com",
            "soundcloud.com",
            "nytimes.com",
            "nyt.com",
            "bbc.com",
            "bbc.co.uk",
            "bbci.co.uk",
            "wsj.com",
            "reuters.com",
            "bloomberg.com",
            "ft.com",
            "economist.com",
            "theguardian.com",
            "cnn.com",
            "apnews.com",
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "epicgames.com",
            "playstation.com",
            "twitchcdn.net",
            // Productivity
            "dropbox.com",
            "dropboxusercontent.com",
            "notion.so",
            "notion.site",
            "figma.com",
            "slack.com",
            "duckduckgo.com",
            "proton.me",
            "protonmail.com",
        ],
        &[],
    )
});

static GEOSITE_GOOGLE: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "google.com",
            "google.cn",
            "g.cn",
            "google.co.jp",
            "google.com.hk",
            "googleapis.com",
            "googleapis.cn",
            "gstatic.com",
            "gstatic.cn",
            "googleusercontent.com",
            "ggpht.com",
            "gvt1.com",
            "gvt2.com",
            "1e100.net",
            "265.com",
            "app-measurement.com",
            "gmail.com",
            "android.com",
            "chromium.org",
            "golang.org",
            "go.dev",
        ],
        &[],
    )
});

static GEOSITE_YOUTUBE: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "youtube.com",
            "youtu.be",
            "ytimg.com",
            "googlevideo.com",
            "youtubei.googleapis.com",
            "youtube-nocookie.com",
            "yt.be",
        ],
        &[],
    )
});

static GEOSITE_GITHUB: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "github.com",
            "github.io",
            "githubusercontent.com",
            "githubassets.com",
            "ghcr.io",
            "githubcopilot.com",
            "git.io",
        ],
        &[],
    )
});

static GEOSITE_OPENAI: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "sora.com",
        ],
        &[],
    )
});

static GEOSITE_ANTHROPIC: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &["anthropic.com", "claude.ai", "claudeusercontent.com"],
        &[],
    )
});

static GEOSITE_NETFLIX: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "netflix.com",
            "netflix.net",
            "nflxext.com",
            "nflximg.com",
            "nflximg.net",
            "nflxso.net",
            "nflxvideo.net",
            "fast.com",
        ],
        &[],
    )
});

static GEOSITE_TELEGRAM: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "telegram.org",
            "telegram.me",
            "t.me",
            "tdesktop.com",
            "telegra.ph",
            "telesco.pe",
        ],
        &[],
    )
});

static GEOSITE_TWITTER: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "twitter.com",
            "x.com",
            "twimg.com",
            "t.co",
            "ads-twitter.com",
            "periscope.tv",
        ],
        &[],
    )
});

static GEOSITE_APPLE: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "apple.com",
            "apple.com.cn",
            "icloud.com",
            "icloud.com.cn",
            "icloud-content.com",
            "mzstatic.com",
            "cdn-apple.com",
            "itunes.com",
            "me.com",
            "aaplimg.com",
        ],
        &[],
    )
});

static GEOSITE_MICROSOFT: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "microsoft.com",
            "s-microsoft.com",
            "microsoftonline.cn",
            "live.com",
            "outlook.com",
            "office.com",
            "office365.com",
            "bing.com",
            "bing.com.cn",
            "msn.com",
            "windows.com",
            "windowsupdate.com",
            "msftconnecttest.com",
            "msftncsi.com",
            "azure.com",
            "azure.cn",
            "visualstudio.com",
        ],
        &[],
    )
});

static GEOSITE_CLOUDFLARE: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "cloudflare.com",
            "cloudflare-dns.com",
            "one.one.one.one",
            "workers.dev",
            "pages.dev",
            "cloudflareclient.com",
        ],
        &[],
    )
});

static GEOSITE_STEAM: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com",
            "steamserver.net",
            "steamgames.com",
            "wmsjsteam.com",
            "dl.steam.clngaa.com",
            "st.dl.eccdnx.com",
            "st.dl.bscstorage.net",
            "st.dl.pinyuncloud.com",
            "valve.software",
        ],
        &[],
    )
});

static GEOSITE_DISCORD: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
        ],
        &[],
    )
});

static GEOSITE_SPOTIFY: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &["spotify.com", "scdn.co", "spotifycdn.com", "pscdn.co"],
        &[],
    )
});

static GEOSITE_ADS: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "adservice.google.com",
            "app-measurement.com",
            "adsrvr.org",
            "adnxs.com",
            "taboola.com",
            "outbrain.com",
            "criteo.com",
            "pos.baidu.com",
            "hm.baidu.com",
        ],
        &["adservice.", "pagead2."],
    )
});

static GEOSITE_GOOGLE_CN: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[
            "dl.google.com",
            "dl-ssl.google.com",
            "tools.google.com",
            "clients1.google.com",
            "clients2.google.com",
            "clients3.google.com",
            "clients4.google.com",
            "update.googleapis.com",
            "translate.googleapis.com",
            "fonts.googleapis.com",
            "fonts.gstatic.com",
            "connectivitycheck.gstatic.com",
        ],
        &[
            "google.cn",
            "g.cn",
            "gstatic.cn",
            "googleapis.cn",
            "265.com",
            "app-measurement.com",
        ],
        &[],
    )
});

static GEOSITE_APPLE_CN: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[
            "captive.apple.com",
            "ls.apple.com",
            "gs.apple.com",
            "xp.apple.com",
            "mesu.apple.com",
            "swscan.apple.com",
            "swdist.apple.com",
            "swcdn.apple.com",
        ],
        &[
            "apple.com.cn",
            "icloud.com.cn",
            "mzstatic.com",
            "cdn-apple.com",
            "aaplimg.com",
        ],
        &[],
    )
});

static GEOSITE_MICROSOFT_CN: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &["cn.bing.com", "officecdn.microsoft.com"],
        &[
            "microsoftonline.cn",
            "azure.cn",
            "bing.com.cn",
            "s-microsoft.com",
            "windowsupdate.com",
            "msftconnecttest.com",
            "msftncsi.com",
        ],
        &[],
    )
});

static GEOSITE_STEAM_CN: LazyLock<GeoSiteMatcher> = LazyLock::new(|| {
    GeoSiteMatcher::from_lists(
        &[],
        &[
            "steamserver.net",
            "steamcontent.com",
            "wmsjsteam.com",
            "dl.steam.clngaa.com",
            "st.dl.eccdnx.com",
            "st.dl.bscstorage.net",
            "st.dl.pinyuncloud.com",
        ],
        &[],
    )
});
