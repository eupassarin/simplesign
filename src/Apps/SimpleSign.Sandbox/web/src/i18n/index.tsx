import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react"
import { en, type Messages } from "./en"
import { ptBR } from "./pt-BR"
import { load, save } from "@/lib/storage"

export type Locale = "en-US" | "pt-BR"

export const locales: { id: Locale; short: string; label: string }[] = [
  { id: "en-US", short: "EN", label: "English (US)" },
  { id: "pt-BR", short: "PT", label: "Português (Brasil)" },
]

const dictionaries: Record<Locale, Messages> = { "en-US": en, "pt-BR": ptBR }

type Join<K, P> = K extends string ? (P extends string ? `${K}.${P}` : never) : never
type Leaves<T> = T extends string ? "" : { [K in keyof T]-?: K extends string ? (T[K] extends string ? K : Join<K, Leaves<T[K]>>) : never }[keyof T]

/** A dotted key of the dictionary, e.g. "pki.revoke". */
export type MessageKey = Leaves<Messages>

function detect(): Locale {
  const saved = load("locale") as Locale | null
  if (saved && saved in dictionaries) return saved
  return (navigator.languages ?? [navigator.language]).some((l) => l.toLowerCase().startsWith("pt")) ? "pt-BR" : "en-US"
}

function lookup(messages: Messages, key: string): string | undefined {
  let node: unknown = messages
  for (const part of key.split(".")) {
    if (typeof node !== "object" || node === null) return undefined
    node = (node as Record<string, unknown>)[part]
  }
  return typeof node === "string" ? node : undefined
}

export type Translate = (key: MessageKey, params?: Record<string, string | number>) => string

interface I18nValue {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: Translate
  date: (value: string) => string
  time: (value: string) => string
}

const I18nContext = createContext<I18nValue | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detect)
  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])
  const setLocale = useCallback((next: Locale) => {
    save("locale", next)
    setLocaleState(next)
  }, [])
  const value = useMemo<I18nValue>(() => {
    const t: Translate = (key, params) => {
      let text = lookup(dictionaries[locale], key) ?? lookup(en, key) ?? key
      if (params) for (const [name, v] of Object.entries(params)) text = text.replaceAll(`{${name}}`, String(v))
      return text
    }
    return {
      locale,
      setLocale,
      t,
      date: (value) => new Date(value).toLocaleDateString(locale),
      time: (value) => new Date(value).toLocaleTimeString(locale),
    }
  }, [locale, setLocale])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nValue {
  const value = useContext(I18nContext)
  if (!value) throw new Error("useI18n outside I18nProvider")
  return value
}
