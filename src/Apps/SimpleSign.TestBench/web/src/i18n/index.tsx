import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react"
import { setApiLocale } from "@/lib/api"
import { en, type Messages } from "./en"
import { es } from "./es"
import { ptBR } from "./pt-BR"

export type Locale = "en-US" | "pt-BR" | "es"

export const locales: { id: Locale; label: string; short: string }[] = [
  { id: "en-US", label: "English (US)", short: "EN" },
  { id: "pt-BR", label: "Português (Brasil)", short: "PT" },
  { id: "es", label: "Español", short: "ES" },
]

const dictionaries: Record<Locale, Messages> = { "en-US": en, "pt-BR": ptBR, es }

type Join<K, P> = K extends string ? (P extends string ? `${K}.${P}` : never) : never
type Leaves<T> = T extends string ? "" : { [K in keyof T]-?: K extends string ? (T[K] extends string ? K : Join<K, Leaves<T[K]>>) : never }[keyof T]

/** A dotted key of the dictionary, e.g. "steps.document.title". */
export type MessageKey = Leaves<Messages>

/** pt* → pt-BR, es* → es, anything else → en-US. */
export function detectLocale(): Locale {
  const saved = localStorage.getItem("locale") as Locale | null
  if (saved && saved in dictionaries) return saved
  for (const language of navigator.languages ?? [navigator.language]) {
    const lower = language.toLowerCase()
    if (lower.startsWith("pt")) return "pt-BR"
    if (lower.startsWith("es")) return "es"
    if (lower.startsWith("en")) return "en-US"
  }
  return "en-US"
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
  /** Formats numbers and dates in the current locale. */
  number: (value: number, digits?: number) => string
  time: (value: string | Date) => string
}

const I18nContext = createContext<I18nValue | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectLocale)
  setApiLocale(locale)
  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])
  const setLocale = useCallback((next: Locale) => {
    localStorage.setItem("locale", next)
    setApiLocale(next)
    setLocaleState(next)
  }, [])
  const value = useMemo<I18nValue>(() => {
    const messages = dictionaries[locale]
    const t: Translate = (key, params) => {
      let text = lookup(messages, key) ?? lookup(en, key) ?? key
      if (params) for (const [name, v] of Object.entries(params)) text = text.replaceAll(`{${name}}`, String(v))
      return text
    }
    const numberFormat = (digits: number) => new Intl.NumberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: digits })
    return {
      locale,
      setLocale,
      t,
      number: (value, digits = 0) => numberFormat(digits).format(value),
      time: (value) => new Date(value).toLocaleTimeString(locale),
    }
  }, [locale, setLocale])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  const context = useContext(I18nContext)
  if (!context) throw new Error("useI18n outside I18nProvider")
  return context
}

export function useT() {
  return useI18n().t
}
