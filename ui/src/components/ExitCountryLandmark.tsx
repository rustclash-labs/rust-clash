import React from "react";

export interface LandmarkRegionMeta {
  flag: string;
  zh: string;
  en: string;
  captionZh: string;
  captionEn: string;
}

const REGION_META: Record<string, LandmarkRegionMeta> = {
  SG: {
    flag: "🇸🇬",
    zh: "新加坡",
    en: "Singapore",
    captionZh: "滨海湾金沙 · 摩天轮",
    captionEn: "Marina Bay Sands · Flyer",
  },
  HK: {
    flag: "🇭🇰",
    zh: "中国香港",
    en: "Hong Kong",
    captionZh: "维多利亚港 · 中银与 IFC",
    captionEn: "Victoria Harbour · BOC & IFC",
  },
  MO: {
    flag: "🇲🇴",
    zh: "中国澳门",
    en: "Macau",
    captionZh: "大三巴 · 澳门旅游塔",
    captionEn: "Macau Tower · Ruins of St. Paul's",
  },
  JP: {
    flag: "🇯🇵",
    zh: "日本",
    en: "Japan",
    captionZh: "富士山 · 东京塔",
    captionEn: "Mt. Fuji · Tokyo Tower",
  },
  TW: {
    flag: "🇹🇼",
    zh: "中国台湾",
    en: "Taiwan",
    captionZh: "台北 101 · 信义天际线",
    captionEn: "Taipei 101 · Xinyi Skyline",
  },
  US: {
    flag: "🇺🇸",
    zh: "美国",
    en: "United States",
    captionZh: "金门大桥 · 湾区剪影",
    captionEn: "Golden Gate Bridge · Bay Area",
  },
  GB: {
    flag: "🇬🇧",
    zh: "英国",
    en: "United Kingdom",
    captionZh: "大本钟 · 伦敦眼",
    captionEn: "Big Ben · London Eye",
  },
  KR: {
    flag: "🇰🇷",
    zh: "韩国",
    en: "South Korea",
    captionZh: "N 首尔塔 · 乐天大厦",
    captionEn: "N Seoul Tower · Lotte World",
  },
  FR: {
    flag: "🇫🇷",
    zh: "法国",
    en: "France",
    captionZh: "埃菲尔铁塔 · 塞纳河",
    captionEn: "Eiffel Tower · Seine",
  },
  DE: {
    flag: "🇩🇪",
    zh: "德国",
    en: "Germany",
    captionZh: "法兰克福 · 勃兰登堡门",
    captionEn: "Frankfurt · Brandenburg Gate",
  },
  NL: {
    flag: "🇳🇱",
    zh: "荷兰",
    en: "Netherlands",
    captionZh: "阿姆斯特丹运河 · 风车",
    captionEn: "Amsterdam Canals · Windmill",
  },
  AU: {
    flag: "🇦🇺",
    zh: "澳大利亚",
    en: "Australia",
    captionZh: "悉尼歌剧院 · 海港大桥",
    captionEn: "Sydney Opera House · Harbour Bridge",
  },
  CA: {
    flag: "🇨🇦",
    zh: "加拿大",
    en: "Canada",
    captionZh: "多伦多 CN 塔 · 安大略湖",
    captionEn: "CN Tower · Lake Ontario",
  },
  CN: {
    flag: "🇨🇳",
    zh: "中国大陆",
    en: "China",
    captionZh: "陆家嘴 · 东方明珠",
    captionEn: "Lujiazui · Oriental Pearl",
  },
};

function isoToFlagEmoji(code: string): string {
  const cc = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc) || cc === "XX") return "";
  return String.fromCodePoint(
    0x1f1e6 + (cc.charCodeAt(0) - 65),
    0x1f1e6 + (cc.charCodeAt(1) - 65),
  );
}

export function landmarkCaptionFor(
  countryCode: string,
  lang: "zh" | "en",
): string {
  const cc = countryCode.trim().toUpperCase();
  const meta = REGION_META[cc];
  if (meta) {
    return lang === "zh" ? meta.captionZh : meta.captionEn;
  }
  return lang === "zh" ? "加密出口 · 全球节点" : "Encrypted Exit · Global";
}

export function countryDisplayFor(
  countryCode: string,
  fallbackCountry: string | undefined,
  lang: "zh" | "en",
): { flag: string; name: string } {
  const cc = countryCode.trim().toUpperCase();
  const meta = REGION_META[cc];
  if (meta) {
    return {
      flag: meta.flag,
      name: lang === "zh" ? meta.zh : meta.en,
    };
  }
  const flag = isoToFlagEmoji(cc);
  const name =
    (fallbackCountry && fallbackCountry.trim()) ||
    (cc && cc !== "XX" && cc !== "IP" ? cc : lang === "zh" ? "加密出口" : "Verified Exit");
  return { flag, name };
}

interface ExitCountryLandmarkProps {
  countryCode: string;
  connected: boolean;
}

function renderSkylineShapes(code: string): React.ReactNode {
  switch (code) {
    case "SG": {
      const spokes = Array.from({ length: 16 }, (_, i) => {
        const a = (i * 22.5 * Math.PI) / 180;
        const x2 = (388 + Math.cos(a) * 34).toFixed(1);
        const y2 = (66 + Math.sin(a) * 34).toFixed(1);
        return (
          <line
            key={i}
            x1="388"
            y1="66"
            x2={x2}
            y2={y2}
            stroke="var(--land-mid)"
            strokeWidth="0.9"
          />
        );
      });
      const capsules = Array.from({ length: 16 }, (_, i) => {
        const a = (i * 22.5 * Math.PI) / 180;
        const cx = (388 + Math.cos(a) * 34).toFixed(1);
        const cy = (66 + Math.sin(a) * 34).toFixed(1);
        return (
          <circle key={i} cx={cx} cy={cy} r="1.8" fill="var(--land-stroke)" />
        );
      });
      return (
        <g>
          {/* Distant CBD towers */}
          <g fill="var(--land-far)">
            <rect x="22" y="64" width="22" height="44" rx="2" />
            <rect x="49" y="50" width="18" height="58" rx="2" />
            <rect x="134" y="66" width="16" height="42" rx="2" />
            <rect x="304" y="54" width="18" height="54" rx="2" />
            <rect x="328" y="66" width="14" height="42" rx="2" />
            <rect x="434" y="58" width="20" height="50" rx="2" />
          </g>
          {/* ArtScience Museum sculpted lotus */}
          <g fill="var(--land-mid)">
            <path d="M84 108 L68 84 Q86 85 95 108 Z" />
            <path d="M90 108 L83 74 Q97 79 101 108 Z" />
            <path d="M96 108 L104 73 Q111 85 106 108 Z" />
            <path d="M102 108 L122 83 Q115 95 110 108 Z" />
            <rect x="82" y="103" width="30" height="5" rx="2" fill="var(--land-near)" />
          </g>
          {/* Marina Bay Sands 3 twin-leg A-frame towers + SkyPark hull */}
          <g fill="var(--land-near)">
            <polygon points="166,108 173,34 189,34 196,108" />
            <polygon points="208,108 215,34 231,34 238,108" />
            <polygon points="250,108 257,34 273,34 280,108" />
            <path
              d="M150 28 Q224 19 298 28 L292 37 Q224 30 155 37 Z"
              fill="var(--land-stroke)"
            />
          </g>
          {/* Architectural tower louver lines */}
          <g stroke="var(--bg-card)" strokeOpacity="0.52" strokeWidth="1.3">
            <line x1="181" y1="38" x2="181" y2="106" />
            <line x1="223" y1="38" x2="223" y2="106" />
            <line x1="265" y1="38" x2="265" y2="106" />
          </g>
          {/* Singapore Flyer */}
          <g>
            {spokes}
            <circle
              cx="388"
              cy="66"
              r="34"
              fill="none"
              stroke="var(--land-stroke)"
              strokeWidth="2.1"
            />
            <circle
              cx="388"
              cy="66"
              r="24"
              fill="none"
              stroke="var(--land-mid)"
              strokeWidth="1"
            />
            {capsules}
            <circle cx="388" cy="66" r="4.2" fill="var(--land-stroke)" />
            <line
              x1="373"
              y1="108"
              x2="388"
              y2="66"
              stroke="var(--land-stroke)"
              strokeWidth="2"
            />
            <line
              x1="403"
              y1="108"
              x2="388"
              y2="66"
              stroke="var(--land-stroke)"
              strokeWidth="2"
            />
          </g>
        </g>
      );
    }

    case "HK":
      return (
        <g>
          <g fill="var(--land-far)">
            <rect x="26" y="64" width="26" height="44" rx="2" />
            <rect x="60" y="52" width="22" height="56" rx="2" />
            <rect x="90" y="70" width="20" height="38" rx="2" />
            <rect x="366" y="56" width="24" height="52" rx="2" />
            <rect x="398" y="66" width="20" height="42" rx="2" />
            <rect x="426" y="74" width="22" height="34" rx="2" />
          </g>
          {/* Two IFC */}
          <g fill="var(--land-mid)">
            <rect x="132" y="28" width="38" height="80" rx="2" />
            <rect x="138" y="20" width="26" height="8" rx="1" />
            <line x1="145" y1="30" x2="145" y2="108" stroke="var(--bg-card)" strokeOpacity="0.45" />
            <line x1="157" y1="30" x2="157" y2="108" stroke="var(--bg-card)" strokeOpacity="0.45" />
          </g>
          {/* Bank of China Tower */}
          <g>
            <polygon points="208,108 208,34 256,18 256,108" fill="var(--land-near)" />
            <line x1="238" y1="24" x2="238" y2="6" stroke="var(--land-stroke)" strokeWidth="1.8" />
            <line x1="248" y1="20" x2="248" y2="4" stroke="var(--land-stroke)" strokeWidth="1.8" />
            <g stroke="var(--bg-card)" strokeOpacity="0.72" strokeWidth="1.4" fill="none">
              <line x1="208" y1="34" x2="256" y2="62" />
              <line x1="256" y1="34" x2="208" y2="62" />
              <line x1="208" y1="62" x2="256" y2="90" />
              <line x1="256" y1="62" x2="208" y2="90" />
              <line x1="208" y1="90" x2="256" y2="108" />
            </g>
          </g>
          {/* HKCEC curved wing roof */}
          <path
            d="M282 108 L282 88 Q316 70 350 88 L350 108 Z"
            fill="var(--land-mid)"
          />
        </g>
      );

    case "JP":
      return (
        <g>
          <circle cx="152" cy="40" r="18" fill="var(--land-far)" />
          {/* Mt. Fuji */}
          <path d="M90 108 Q168 78 198 32 L228 32 Q258 78 334 108 Z" fill="var(--land-mid)" />
          <path
            d="M191 45 L198 32 L228 32 L235 45 L224 42 L217 49 L209 42 L200 48 Z"
            fill="var(--bg-card)"
            fillOpacity="0.9"
          />
          {/* Torii Gate */}
          <g fill="var(--land-stroke)">
            <path d="M56 72 Q86 77 116 72 L114 77 Q86 81 58 77 Z" />
            <rect x="63" y="82" width="46" height="3.5" rx="1" />
            <rect x="70" y="75" width="4.5" height="33" />
            <rect x="97.5" y="75" width="4.5" height="33" />
          </g>
          {/* Tokyo Tower */}
          <g fill="var(--land-near)" stroke="var(--land-stroke)" strokeWidth="1.2">
            <path d="M364 108 Q380 72 386 18 L390 18 Q396 72 412 108 L403 108 Q392 88 388 88 Q384 88 373 108 Z" />
            <rect x="378" y="64" width="20" height="5" rx="1" />
            <rect x="382" y="42" width="12" height="4" rx="1" />
            <line x1="388" y1="18" x2="388" y2="6" strokeWidth="2" />
          </g>
        </g>
      );

    case "TW":
      return (
        <g>
          <g fill="var(--land-far)">
            <rect x="38" y="68" width="26" height="40" rx="2" />
            <rect x="72" y="56" width="24" height="52" rx="2" />
            <rect x="116" y="74" width="28" height="34" rx="2" />
            <rect x="322" y="64" width="26" height="44" rx="2" />
            <rect x="356" y="52" width="22" height="56" rx="2" />
            <rect x="386" y="72" width="32" height="36" rx="2" />
          </g>
          {/* Taipei 101 stacked pagoda segments */}
          <g fill="var(--land-near)">
            <polygon points="212,108 216,90 256,90 260,108" />
            <polygon points="214,90 218,76 254,76 258,90" />
            <polygon points="216,76 220,62 252,62 256,76" />
            <polygon points="218,62 222,48 250,48 254,62" />
            <polygon points="220,48 224,34 248,34 252,48" />
            <rect x="228" y="24" width="16" height="10" rx="1" fill="var(--land-stroke)" />
            <line x1="236" y1="24" x2="236" y2="6" stroke="var(--land-stroke)" strokeWidth="2.2" />
          </g>
          <g stroke="var(--bg-card)" strokeOpacity="0.65" strokeWidth="1.1">
            <line x1="215" y1="90" x2="257" y2="90" />
            <line x1="217" y1="76" x2="255" y2="76" />
            <line x1="219" y1="62" x2="253" y2="62" />
            <line x1="221" y1="48" x2="251" y2="48" />
          </g>
        </g>
      );

    case "US":
      return (
        <g>
          <g fill="var(--land-far)">
            <rect x="24" y="74" width="18" height="34" rx="2" />
            <rect x="46" y="62" width="16" height="46" rx="2" />
            <rect x="408" y="66" width="20" height="42" rx="2" />
            <rect x="434" y="74" width="16" height="34" rx="2" />
          </g>
          <path
            d="M22 90 Q90 92 150 28 Q238 92 326 28 Q386 92 454 90"
            fill="none"
            stroke="var(--land-stroke)"
            strokeWidth="2.4"
          />
          <g stroke="var(--land-mid)" strokeWidth="1.1">
            <line x1="180" y1="53" x2="180" y2="90" />
            <line x1="208" y1="67" x2="208" y2="90" />
            <line x1="238" y1="73" x2="238" y2="90" />
            <line x1="268" y1="67" x2="268" y2="90" />
            <line x1="296" y1="53" x2="296" y2="90" />
          </g>
          <rect x="22" y="88" width="432" height="4.5" rx="2" fill="var(--land-stroke)" />
          <g fill="var(--land-near)">
            <rect x="142" y="24" width="6" height="84" rx="1" />
            <rect x="154" y="24" width="6" height="84" rx="1" />
            <rect x="142" y="34" width="18" height="4" />
            <rect x="142" y="54" width="18" height="4" />
            <rect x="142" y="74" width="18" height="4" />
            <rect x="318" y="24" width="6" height="84" rx="1" />
            <rect x="330" y="24" width="6" height="84" rx="1" />
            <rect x="318" y="34" width="18" height="4" />
            <rect x="318" y="54" width="18" height="4" />
            <rect x="318" y="74" width="18" height="4" />
          </g>
        </g>
      );

    case "GB": {
      const spokes = Array.from({ length: 12 }, (_, i) => {
        const a = (i * 30 * Math.PI) / 180;
        return (
          <line
            key={i}
            x1="340"
            y1="66"
            x2={(340 + Math.cos(a) * 34).toFixed(1)}
            y2={(66 + Math.sin(a) * 34).toFixed(1)}
            stroke="var(--land-mid)"
            strokeWidth="1"
          />
        );
      });
      return (
        <g>
          {/* Houses of Parliament */}
          <rect x="52" y="74" width="110" height="34" rx="2" fill="var(--land-mid)" />
          {/* Big Ben */}
          <g fill="var(--land-near)">
            <rect x="164" y="36" width="24" height="72" rx="1" />
            <polygon points="162,36 176,12 190,36" fill="var(--land-stroke)" />
            <circle cx="176" cy="48" r="6" fill="var(--bg-card)" fillOpacity="0.85" />
          </g>
          {/* London Eye */}
          <g>
            {spokes}
            <circle cx="340" cy="66" r="34" fill="none" stroke="var(--land-stroke)" strokeWidth="2.2" />
            <line x1="324" y1="108" x2="340" y2="66" stroke="var(--land-stroke)" strokeWidth="2" />
            <line x1="356" y1="108" x2="340" y2="66" stroke="var(--land-stroke)" strokeWidth="2" />
          </g>
        </g>
      );
    }

    case "KR":
      return (
        <g>
          {/* Namsan hill + N Seoul Tower */}
          <path d="M56 108 Q138 66 218 108 Z" fill="var(--land-mid)" />
          <g fill="var(--land-near)">
            <rect x="134" y="30" width="8" height="56" />
            <rect x="124" y="36" width="28" height="10" rx="3" fill="var(--land-stroke)" />
            <line x1="138" y1="30" x2="138" y2="12" stroke="var(--land-stroke)" strokeWidth="2" />
          </g>
          {/* Lotte World Tower */}
          <polygon points="316,108 328,14 338,14 352,108" fill="var(--land-near)" />
          <line x1="333" y1="18" x2="333" y2="106" stroke="var(--bg-card)" strokeOpacity="0.55" strokeWidth="1.3" />
          <g fill="var(--land-far)">
            <rect x="250" y="68" width="24" height="40" rx="2" />
            <rect x="280" y="58" width="22" height="50" rx="2" />
            <rect x="366" y="64" width="26" height="44" rx="2" />
          </g>
        </g>
      );

    case "FR":
      return (
        <g>
          <g fill="var(--land-far)">
            <rect x="44" y="76" width="52" height="32" rx="2" />
            <rect x="366" y="74" width="56" height="34" rx="2" />
          </g>
          {/* Eiffel Tower */}
          <g fill="var(--land-near)" stroke="var(--land-stroke)" strokeWidth="1.2">
            <path d="M196 108 Q224 72 234 12 L242 12 Q252 72 280 108 L266 108 Q250 86 238 86 Q226 86 210 108 Z" />
            <rect x="218" y="68" width="40" height="5" rx="1" />
            <rect x="226" y="44" width="24" height="4.5" rx="1" />
            <line x1="238" y1="12" x2="238" y2="3" strokeWidth="2" />
          </g>
        </g>
      );

    case "DE":
      return (
        <g>
          {/* Frankfurt skyline (left) */}
          <g fill="var(--land-far)">
            <rect x="34" y="56" width="22" height="52" rx="2" />
            <polygon points="64,108 64,42 84,32 84,108" fill="var(--land-mid)" />
            <rect x="92" y="62" width="20" height="46" rx="2" />
          </g>
          {/* Brandenburg Gate (center-right) */}
          <g fill="var(--land-near)">
            <rect x="196" y="50" width="144" height="10" rx="2" fill="var(--land-stroke)" />
            <rect x="242" y="38" width="52" height="12" rx="2" fill="var(--land-stroke)" />
            <rect x="204" y="60" width="10" height="48" />
            <rect x="228" y="60" width="10" height="48" />
            <rect x="252" y="60" width="10" height="48" />
            <rect x="274" y="60" width="10" height="48" />
            <rect x="298" y="60" width="10" height="48" />
            <rect x="322" y="60" width="10" height="48" />
          </g>
        </g>
      );

    case "NL":
      return (
        <g>
          {/* Amsterdam stepped gable canal houses */}
          <g fill="var(--land-mid)">
            <path d="M58 108 L58 64 L66 64 L66 56 L78 56 L78 64 L86 64 L86 108 Z" />
            <path d="M92 108 L92 60 L106 48 L120 60 L120 108 Z" />
            <path d="M126 108 L126 66 L134 66 L134 58 L146 58 L146 66 L154 66 L154 108 Z" />
          </g>
          {/* Windmill */}
          <g>
            <polygon points="310,108 322,48 346,48 358,108" fill="var(--land-near)" />
            <path d="M320 48 Q334 34 348 48 Z" fill="var(--land-stroke)" />
            <g stroke="var(--land-stroke)" strokeWidth="2.4" strokeLinecap="round">
              <line x1="300" y1="22" x2="368" y2="82" />
              <line x1="368" y1="22" x2="300" y2="82" />
            </g>
            <circle cx="334" cy="52" r="4" fill="var(--land-stroke)" />
          </g>
        </g>
      );

    case "AU":
      return (
        <g>
          {/* Sydney Harbour Bridge */}
          <path d="M40 100 Q124 30 208 100" fill="none" stroke="var(--land-mid)" strokeWidth="3" />
          <line x1="32" y1="90" x2="216" y2="90" stroke="var(--land-stroke)" strokeWidth="2.4" />
          {/* Sydney Opera House Sails */}
          <g fill="var(--land-near)">
            <path d="M220 108 Q232 60 264 56 Q256 86 260 108 Z" />
            <path d="M254 108 Q272 44 316 40 Q304 82 308 108 Z" />
            <path d="M300 108 Q320 56 356 54 Q346 86 350 108 Z" />
            <path d="M342 108 Q364 74 396 72 Q388 94 392 108 Z" fill="var(--land-mid)" />
          </g>
        </g>
      );

    case "CA":
      return (
        <g>
          <g fill="var(--land-far)">
            <rect x="64" y="64" width="26" height="44" rx="2" />
            <rect x="98" y="54" width="24" height="54" rx="2" />
            <rect x="296" y="58" width="26" height="50" rx="2" />
            <rect x="330" y="68" width="24" height="40" rx="2" />
          </g>
          {/* CN Tower */}
          <g fill="var(--land-near)">
            <polygon points="222,108 232,18 240,18 250,108" />
            <ellipse cx="236" cy="40" rx="18" ry="6" fill="var(--land-stroke)" />
            <line x1="236" y1="18" x2="236" y2="4" stroke="var(--land-stroke)" strokeWidth="2.2" />
          </g>
        </g>
      );

    case "CN":
      return (
        <g>
          {/* Shanghai Tower + SWFC */}
          <g fill="var(--land-mid)">
            <polygon points="292,108 302,26 322,22 332,108" />
            <polygon points="348,108 352,42 374,42 378,108" />
            <rect x="357" y="48" width="12" height="8" fill="var(--bg-card)" fillOpacity="0.8" />
          </g>
          {/* Oriental Pearl Tower */}
          <g fill="var(--land-near)" stroke="var(--land-stroke)" strokeWidth="1.6">
            <line x1="176" y1="108" x2="176" y2="12" />
            <line x1="154" y1="108" x2="176" y2="74" />
            <line x1="198" y1="108" x2="176" y2="74" />
            <circle cx="176" cy="74" r="12" />
            <circle cx="176" cy="42" r="8" />
            <circle cx="176" cy="24" r="3.5" fill="var(--land-stroke)" />
          </g>
        </g>
      );

    case "MO":
      return (
        <g>
          {/* Ruins of St. Paul's facade */}
          <g fill="var(--land-mid)">
            <rect x="92" y="54" width="66" height="54" rx="2" />
            <polygon points="104,54 125,36 146,54" fill="var(--land-stroke)" />
          </g>
          {/* Macau Tower */}
          <g fill="var(--land-near)">
            <polygon points="318,108 326,20 334,20 342,108" />
            <rect x="316" y="38" width="28" height="8" rx="3" fill="var(--land-stroke)" />
            <line x1="330" y1="20" x2="330" y2="5" stroke="var(--land-stroke)" strokeWidth="2" />
          </g>
        </g>
      );

    default:
      return null;
  }
}

export const ExitCountryLandmark: React.FC<ExitCountryLandmarkProps> = ({
  countryCode,
  connected,
}) => {
  const code = countryCode.trim().toUpperCase();
  const hasSkyline = Boolean(connected && REGION_META[code]);

  if (!hasSkyline) {
    return (
      <svg
        className="exit-landmark-svg"
        viewBox="0 0 476 136"
        preserveAspectRatio="xMidYMax meet"
        aria-hidden="true"
      >
        <g
          opacity={connected ? 0.72 : 0.48}
          fill="none"
          stroke="var(--land-mid)"
          strokeWidth="1.4"
        >
          <circle cx="238" cy="68" r="42" />
          <ellipse cx="238" cy="68" rx="20" ry="42" />
          <line x1="196" y1="68" x2="280" y2="68" />
          <path d="M202 48 Q238 56 274 48" />
          <path d="M202 88 Q238 80 274 88" />
        </g>
        <line
          x1="18"
          y1="118"
          x2="458"
          y2="118"
          stroke="var(--land-far)"
          strokeWidth="1.2"
        />
      </svg>
    );
  }

  const shapes = renderSkylineShapes(code);

  return (
    <svg
      className="exit-landmark-svg"
      viewBox="0 0 476 136"
      preserveAspectRatio="xMidYMax meet"
      aria-hidden="true"
    >
      <defs>
        <clipPath id={`sky-clip-${code}`}>
          <rect x="0" y="0" width="476" height="108.5" />
        </clipPath>
        <clipPath id={`water-clip-${code}`}>
          <rect x="0" y="108" width="476" height="28" />
        </clipPath>
      </defs>

      {/* Primary skyline above waterline */}
      <g clipPath={`url(#sky-clip-${code})`}>{shapes}</g>

      {/* Waterfront mirrored reflection */}
      <g clipPath={`url(#water-clip-${code})`}>
        <rect x="0" y="108" width="476" height="28" fill="var(--land-water)" />
        <g
          opacity="0.32"
          transform="translate(0, 108) scale(1, -0.34) translate(0, -108)"
        >
          {shapes}
        </g>
        {/* Subtle water ripples */}
        <g
          stroke="var(--bg-card)"
          strokeOpacity="0.45"
          strokeWidth="1.1"
          strokeLinecap="round"
        >
          <line x1="48" y1="115" x2="128" y2="115" />
          <line x1="168" y1="117" x2="310" y2="117" />
          <line x1="352" y1="115" x2="432" y2="115" />
          <line x1="112" y1="124" x2="236" y2="124" />
          <line x1="274" y1="126" x2="386" y2="126" />
        </g>
      </g>

      {/* Crisp shoreline promenade */}
      <line
        x1="14"
        y1="108"
        x2="462"
        y2="108"
        stroke="var(--land-mid)"
        strokeWidth="1"
      />
    </svg>
  );
};
