import enUS from "./locales/en-US.json";
import ptBR from "./locales/pt-BR.json";

const locales: Record<string, Record<string, string>> = {
  "en-US": enUS,
  "pt-BR": ptBR,
};

export const supportedLocales = [
  { code: "en-US", label: "English" },
  { code: "pt-BR", label: "Português" },
];

function detectLocale(): string {
  const saved = localStorage.getItem("simplesign-locale");
  if (saved && locales[saved]) return saved;
  const lang = navigator.language;
  if (lang.startsWith("pt")) return "pt-BR";
  return "en-US";
}

let currentLocale = detectLocale();
let messages = locales[currentLocale] || locales["en-US"];

let listeners: Array<() => void> = [];

export function onLocaleChange(fn: () => void) {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
  };
}

export function setLocale(code: string) {
  if (locales[code]) {
    currentLocale = code;
    messages = locales[code];
    localStorage.setItem("simplesign-locale", code);
    listeners.forEach((fn) => fn());
  }
}

export function getLocale(): string {
  return currentLocale;
}

export function t(key: string): string {
  return messages[key] || key;
}
