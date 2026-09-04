import zhHant, { type Dict } from "./locales/zh-Hant";
import zhHans from "./locales/zh-Hans";
import en from "./locales/en";
import ja from "./locales/ja";
import ko from "./locales/ko";

export type Locale = "zh-Hant" | "zh-Hans" | "en" | "ja" | "ko";
export type Key = keyof Dict;

/// Order shown in the picker. `native` is the language's own name — that is
/// what someone looking for their language actually scans for, and it is
/// readable even when the UI is currently in a language they cannot read.
export const LOCALES: { code: Locale; native: string }[] = [
  { code: "zh-Hant", native: "繁體中文" },
  { code: "zh-Hans", native: "简体中文" },
  { code: "en", native: "English" },
  { code: "ja", native: "日本語" },
  { code: "ko", native: "한국어" },
];

const dict: Record<Locale, Dict> = { "zh-Hant": zhHant, "zh-Hans": zhHans, en, ja, ko };

/// Pick a locale from BCP-47 tags, most-preferred first. Chinese needs care:
/// `zh-TW`, `zh-HK` and `zh-Hant-*` are Traditional; a bare `zh` or `zh-CN` is
/// Simplified. Everything unknown falls through to English rather than to
/// whichever language happens to be first in the list.
export function resolveLocale(tags: readonly string[]): Locale {
  for (const raw of tags) {
    const tag = raw.toLowerCase();
    if (tag.startsWith("zh")) {
      const traditional = /hant|-tw|-hk|-mo/.test(tag);
      return traditional ? "zh-Hant" : "zh-Hans";
    }
    if (tag.startsWith("ja")) return "ja";
    if (tag.startsWith("ko")) return "ko";
    if (tag.startsWith("en")) return "en";
  }
  return "en";
}

export function isLocale(v: unknown): v is Locale {
  return typeof v === "string" && LOCALES.some((l) => l.code === v);
}

export function makeT(locale: Locale) {
  return (k: Key, vars?: Record<string, string | number>) => {
    let s: string = dict[locale][k] ?? k;
    if (vars) for (const [name, v] of Object.entries(vars)) s = s.replace(`{${name}}`, String(v));
    return s;
  };
}
