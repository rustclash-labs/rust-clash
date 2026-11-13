import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

export type Lang = "zh" | "en";

export const LANG_STORAGE_KEY = "rust_clash_lang_v1";
export const THEME_STORAGE_KEY = "rust_clash_ui_theme_v2";

export function detectDefaultLang(): Lang {
  if (typeof window !== "undefined") {
    try {
      const saved = localStorage.getItem(LANG_STORAGE_KEY);
      if (saved === "zh" || saved === "en") {
        return saved;
      }
    } catch {
      // ignore restricted storage
    }
  }
  const navLang =
    typeof navigator !== "undefined" && typeof navigator.language === "string"
      ? navigator.language
      : "zh-CN";
  return navLang.startsWith("zh") ? "zh" : "zh";
}

export function loadInitialTheme(): "light" | "dark" {
  if (typeof window !== "undefined") {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === "dark" || saved === "light") {
        return saved;
      }
    } catch {
      // ignore restricted storage
    }
  }
  return "light";
}

export function saveThemePreference(theme: "light" | "dark"): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // ignore restricted storage
  }
}

export interface I18nContextValue {
  lang: Lang;
  setLang: (next: Lang) => void;
  toggleLang: () => void;
  tr: (zh: string, en: string) => string;
}

const I18nContext = createContext<I18nContextValue>({
  lang: "zh",
  setLang: () => undefined,
  toggleLang: () => undefined,
  tr: (zh) => zh,
});

export const I18nProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [lang, setLangState] = useState<Lang>(() => detectDefaultLang());

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    try {
      localStorage.setItem(LANG_STORAGE_KEY, next);
    } catch {
      // ignore restricted storage
    }
  }, []);

  const toggleLang = useCallback(() => {
    setLang(lang === "zh" ? "en" : "zh");
  }, [lang, setLang]);

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    }
  }, [lang]);

  const tr = useCallback(
    (zh: string, en: string) => (lang === "zh" ? zh : en),
    [lang],
  );

  const value = useMemo<I18nContextValue>(
    () => ({ lang, setLang, toggleLang, tr }),
    [lang, setLang, toggleLang, tr],
  );

  return React.createElement(I18nContext.Provider, { value }, children);
};

export function useI18n(): I18nContextValue {
  return useContext(I18nContext);
}
