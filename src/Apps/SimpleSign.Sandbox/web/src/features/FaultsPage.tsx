import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Input } from "@/components/ui/input"
import { Section } from "@/components/parts"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { CrlFault, OcspFault, OcspSigner, SandboxFaults, TlFault, TsaFault } from "@/lib/types"
import { cn } from "@/lib/utils"

const tsaValues: TsaFault[] = ["None", "Down", "Slow", "InvalidToken", "Untrusted"]
const crlValues: CrlFault[] = ["None", "Down", "Slow", "Expired", "WrongKey", "Stale"]
const ocspValues: OcspFault[] = ["None", "Down", "Slow", "TryLater", "Expired", "Unauthorized", "Unknown"]
const signerValues: OcspSigner[] = ["Issuer", "Delegated"]
const tlValues: TlFault[] = ["None", "Expired", "WrongSigner", "Tampered"]

/** Switch failures of the TSA, the CRL server (HTTP, HTTPS, LDAP), the OCSP responder and the trusted list on and off. */
export function FaultsPage({ onChanged }: { onChanged: (faults: SandboxFaults) => void }) {
  const { t } = useI18n()
  const [faults, setFaults] = useState<SandboxFaults | null>(null)
  useEffect(() => {
    api.faults().then(setFaults).catch(() => setFaults(null))
  }, [])
  const save = async (next: SandboxFaults) => {
    setFaults(next)
    try {
      const saved = await api.setFaults(next)
      setFaults(saved)
      onChanged(saved)
      toast.success(t("faults.saved"))
    } catch (e) {
      toast.error(t("common.error"), { description: (e as Error).message })
    }
  }
  if (!faults) return <p className="text-muted-foreground text-sm">{t("common.loading")}</p>
  return (
    <div className="space-y-8">
      <p className="text-muted-foreground max-w-3xl text-sm">{t("faults.intro")}</p>
      <div className="grid gap-8 lg:grid-cols-3">
        <Group title={t("faults.crl")} values={crlValues} current={faults.crl} prefix="faults.crlValues" onChoose={(v) => save({ ...faults, crl: v as CrlFault })}
          delay={faults.crl === "Slow" ? faults.crlDelayMs : null} onDelay={(ms) => save({ ...faults, crlDelayMs: ms })} />
        <div className="space-y-8">
          <Group title={t("faults.ocsp")} values={ocspValues} current={faults.ocsp} prefix="faults.ocspValues" onChoose={(v) => save({ ...faults, ocsp: v as OcspFault })}
            delay={faults.ocsp === "Slow" ? faults.ocspDelayMs : null} onDelay={(ms) => save({ ...faults, ocspDelayMs: ms })} />
          <Group title={t("faults.ocspSigner")} values={signerValues} current={faults.ocspSigner} prefix="faults.signerValues" neutral
            onChoose={(v) => save({ ...faults, ocspSigner: v as OcspSigner })} delay={null} onDelay={() => {}} />
        </div>
        <div className="space-y-8">
          <Group title={t("faults.tsa")} values={tsaValues} current={faults.tsa} prefix="faults.tsaValues" onChoose={(v) => save({ ...faults, tsa: v as TsaFault })}
            delay={faults.tsa === "Slow" ? faults.tsaDelayMs : null} onDelay={(ms) => save({ ...faults, tsaDelayMs: ms })} />
          <Group title={t("faults.trustedList")} values={tlValues} current={faults.trustedList ?? "None"} prefix="faults.tlValues"
            onChoose={(v) => save({ ...faults, trustedList: v as TlFault })} delay={null} onDelay={() => {}} />
        </div>
      </div>
    </div>
  )
}

function Group({ title, values, current, prefix, onChoose, delay, onDelay, neutral }: {
  title: string
  values: string[]
  current: string
  prefix: "faults.tsaValues" | "faults.crlValues" | "faults.ocspValues" | "faults.signerValues" | "faults.tlValues"
  onChoose: (value: string) => void
  delay: number | null
  onDelay: (ms: number) => void
  /** A choice, not a failure: the selected value is not shown as one. */
  neutral?: boolean
}) {
  const { t } = useI18n()
  const [ms, setMs] = useState(String(delay ?? 3000))
  return (
    <Section title={title}>
      <div className="grid gap-2" role="radiogroup" aria-label={title}>
        {values.map((v, i) => (
          <button key={v} type="button" role="radio" aria-checked={current === v} onClick={() => onChoose(v)}
            className={cn("rounded-lg border p-3 text-left transition-colors", current === v ? "border-primary bg-accent/60 ring-primary/20 ring-1" : "hover:bg-accent/30",
              current === v && i > 0 && !neutral && "border-destructive/60 bg-destructive/5")}>
            <span className="block text-sm font-medium">{t(`${prefix}.${v}.title` as MessageKey)}</span>
            <span className="text-muted-foreground block text-xs">{t(`${prefix}.${v}.hint` as MessageKey)}</span>
          </button>
        ))}
      </div>
      {delay !== null && (
        <label className="flex items-center gap-2 text-sm">
          {t("faults.delay")}
          <Input className="w-28" type="number" min={0} max={60000} step={500} value={ms} onChange={(e) => setMs(e.target.value)}
            onBlur={() => onDelay(Math.max(0, Math.min(60000, Number(ms) || 0)))} />
        </label>
      )}
    </Section>
  )
}
