import { useMemo } from "react"
import { useI18n as useAppI18n, type MessageKey as AppKey } from "@/i18n"
import type { SandboxMessages } from "@/i18n/sandbox.en"

type Join<K, P> = K extends string ? (P extends string ? `${K}.${P}` : never) : never
type Leaves<T> = T extends string ? "" : { [K in keyof T]-?: K extends string ? (T[K] extends string ? K : Join<K, Leaves<T[K]>>) : never }[keyof T]

/** A dotted key of the Sandbox controls' dictionary (i18n/sandbox.en.ts), e.g. "pki.revoke". */
export type MessageKey = Leaves<SandboxMessages>

/** The TestBench's language, with the Sandbox controls' keys (mounted under "sbx" in the app's dictionary). */
export function useI18n() {
  const app = useAppI18n()
  return useMemo(() => ({
    locale: app.locale,
    t: (key: MessageKey, params?: Record<string, string | number>) => app.t(`sbx.${key}` as AppKey, params),
    date: (value: string) => new Date(value).toLocaleDateString(app.locale),
    time: (value: string) => new Date(value).toLocaleTimeString(app.locale),
  }), [app])
}
