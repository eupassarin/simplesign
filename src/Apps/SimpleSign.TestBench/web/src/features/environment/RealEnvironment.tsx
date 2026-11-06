import { useEffect, useState } from "react"
import { Clock, Cloud, KeyRound, ShieldCheck, Usb } from "lucide-react"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { Pkcs11Driver, StoreCertificate } from "@/lib/types"
import { KeyValue, Pill, Section } from "../shared/ui"
import type { RealEnvironment as RealEnvironmentView } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"

/**
 * The Real environment: nothing is simulated, so this shows what really exists on this machine
 * and on the internet for the library to use: the roots validation trusts, the public TSAs, the
 * keys (tokens and the OS store), what a cloud provider needs, and DSS.
 */
export function RealEnvironment() {
  const { env, dssStatus, checkDss } = useWorkbench()
  const { t } = useI18n()
  const [real, setReal] = useState<RealEnvironmentView | null>(null)
  const [drivers, setDrivers] = useState<Pkcs11Driver[] | null>(null)
  const [store, setStore] = useState<StoreCertificate[] | null>(null)
  const [showRoots, setShowRoots] = useState(false)
  useEffect(() => {
    api.environment.real().then(setReal).catch(() => setReal(null))
    api.credentials.pkcs11().then(setDrivers).catch(() => setDrivers([]))
    api.credentials.store().then(setStore).catch(() => setStore([]))
    void checkDss()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const tokens = drivers?.flatMap((d) => d.tokens) ?? []
  const sources = [...new Set(real?.bundledRoots.map((r) => r.source) ?? [])]
  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="space-y-8 p-6 lg:p-8">
        <header className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">{t("real.title")}</h2>
          <p className="text-muted-foreground max-w-3xl text-sm">{t("real.intro")}</p>
        </header>

        <Section title={t("real.trust")} description={t("real.trustHint")}>
          <div className="rounded-lg border px-4 py-2">
            <KeyValue label={t("real.systemRoots")}>{real?.systemRootCount ?? "—"}</KeyValue>
            {sources.map((source) => (
              <KeyValue key={source} label={t("real.bundledRoots", { source })}>{real!.bundledRoots.filter((r) => r.source === source).length}</KeyValue>
            ))}
            <button type="button" className="text-muted-foreground hover:text-foreground py-1.5 text-xs underline underline-offset-2" onClick={() => setShowRoots(!showRoots)}>
              {t(showRoots ? "real.hideRoots" : "real.showRoots")}
            </button>
            {showRoots && (
              <ul className="divide-y border-t">
                {real?.bundledRoots.map((r) => (
                  <li key={r.thumbprint} className="flex flex-wrap items-baseline gap-x-3 py-1.5 text-xs">
                    <Pill>{r.source}</Pill>
                    <span className="min-w-0 flex-1 break-words">{r.subject}</span>
                    <span className="text-muted-foreground shrink-0 tabular-nums">→ {r.notAfter}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Section>

        <Section title={t("real.tsa")} description={t("real.tsaHint")}>
          <div className="grid gap-4 md:grid-cols-3">
            {real?.publicTsas.map((tsa) => (
              <div key={tsa.name} className="rounded-lg border p-4">
                <p className="flex items-center gap-2 text-sm font-medium"><Clock className="size-4" /> {tsa.name}</p>
                <KeyValue stacked mono label="URL" copy={tsa.url}>{tsa.url}</KeyValue>
                <KeyValue stacked mono label="API">{tsa.api}</KeyValue>
              </div>
            ))}
          </div>
        </Section>

        <Section title={t("real.keys")} description={t("real.keysHint")}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border p-4">
              <p className="flex items-center gap-2 text-sm font-medium"><Usb className="size-4" /> {t("real.tokens")}</p>
              {drivers === null ? <p className="text-muted-foreground text-xs">…</p> : drivers.length === 0 ? <p className="text-muted-foreground text-xs">{t("real.noDrivers")}</p> : (
                <ul className="divide-y">
                  {drivers.map((d) => (
                    <li key={d.libraryPath} className="py-1.5 text-xs">
                      <span className="flex flex-wrap items-center gap-2"><span className="font-medium">{d.driver}</span><Pill tone={d.tokens.length > 0 ? "success" : "default"}>{t("real.tokenCount", { n: d.tokens.length })}</Pill></span>
                      <span className="text-muted-foreground block font-mono break-all">{d.libraryPath}</span>
                      {d.error && <span className="text-muted-foreground block break-words">{d.error}</span>}
                    </li>
                  ))}
                </ul>
              )}
              {drivers !== null && tokens.length === 0 && <p className="text-muted-foreground pt-2 text-xs leading-relaxed">{t("real.noTokens")}</p>}
            </div>
            <div className="rounded-lg border p-4">
              <p className="flex items-center gap-2 text-sm font-medium"><KeyRound className="size-4" /> {t("real.store")}</p>
              {store === null ? <p className="text-muted-foreground text-xs">…</p> : store.length === 0 ? <p className="text-muted-foreground text-xs">{t("real.noStore")}</p> : (
                <ul className="divide-y">
                  {store.slice(0, 12).map((c) => (
                    <li key={c.thumbprint} className="py-1.5 text-xs">
                      <span className="font-medium">{c.holder}</span>
                      <span className="text-muted-foreground block break-words">{c.issuer} · → {c.notAfter}</span>
                    </li>
                  ))}
                </ul>
              )}
              {store !== null && store.length > 12 && <p className="text-muted-foreground pt-2 text-xs">+{store.length - 12}</p>}
            </div>
          </div>
        </Section>

        <Section title={t("real.cloud")} description={t("real.cloudHint")}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2 rounded-lg border p-4">
              <p className="flex items-center gap-2 text-sm font-medium"><Cloud className="size-4" /> PSC (DOC-ICP-17.01)</p>
              <p className="text-muted-foreground text-xs leading-relaxed">{t("signer.cloud.psc.what")}</p>
              <p className="text-xs leading-relaxed">{t("real.pscNeeds")}</p>
            </div>
            <div className="space-y-2 rounded-lg border p-4">
              <p className="flex items-center gap-2 text-sm font-medium"><Cloud className="size-4" /> CSC API v2</p>
              <p className="text-muted-foreground text-xs leading-relaxed">{t("signer.cloud.csc.what")}</p>
              <p className="text-xs leading-relaxed">{t("real.cscNeeds")}</p>
            </div>
          </div>
        </Section>

        <Section title="DSS" description={t("real.dssHint")}>
          <div className="rounded-lg border px-4 py-2">
            <KeyValue stacked mono label="URL" copy={dssStatus?.url}>{dssStatus?.url}</KeyValue>
            <KeyValue label={t("sandbox.status")}>{dssStatus ? (dssStatus.reachable ? <Pill tone="success">{t("lab.dssUp", { ms: dssStatus.ms })}</Pill> : <Pill>{t("lab.dssDown")}</Pill>) : "—"}</KeyValue>
          </div>
        </Section>

        <p className="text-muted-foreground flex items-center gap-1.5 text-xs"><ShieldCheck className="size-3.5" /> {env?.runtime} · SimpleSign {env?.version} · SHA-3 {t(env?.sha3Supported ? "sandbox.available" : "sandbox.notAvailable")}</p>
      </div>
    </div>
  )
}
