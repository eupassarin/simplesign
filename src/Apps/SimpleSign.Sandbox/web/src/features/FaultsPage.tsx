import { useEffect, useState } from "react"
import { PowerOff } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/parts"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { SandboxFaults } from "@/lib/types"
import { cn } from "@/lib/utils"

type Prefix = "faults.tsaValues" | "faults.crlValues" | "faults.ocspValues" | "faults.signerValues" | "faults.tlValues"

/** One row: a service, its values, the delay field that applies when it is Slow. */
interface Row {
  field: "crl" | "ocsp" | "ocspSigner" | "tsa" | "trustedList"
  title: MessageKey
  values: string[]
  prefix: Prefix
  delay?: "crlDelayMs" | "ocspDelayMs" | "tsaDelayMs"
  /** A choice, not a failure: a value other than the first is not shown as one. */
  neutral?: boolean
}

const rows: Row[] = [
  { field: "crl", title: "faults.crl", values: ["None", "Down", "Slow", "Expired", "WrongKey", "Stale"], prefix: "faults.crlValues", delay: "crlDelayMs" },
  { field: "ocsp", title: "faults.ocsp", values: ["None", "Down", "Slow", "TryLater", "Expired", "Unauthorized", "Unknown"], prefix: "faults.ocspValues", delay: "ocspDelayMs" },
  { field: "ocspSigner", title: "faults.ocspSigner", values: ["Issuer", "Delegated"], prefix: "faults.signerValues", neutral: true },
  { field: "tsa", title: "faults.tsa", values: ["None", "Down", "Slow", "InvalidToken", "Untrusted"], prefix: "faults.tsaValues", delay: "tsaDelayMs" },
  { field: "trustedList", title: "faults.trustedList", values: ["None", "Expired", "WrongSigner", "Tampered"], prefix: "faults.tlValues" },
]

/** Switch failures of the CRL server (HTTP, HTTPS, LDAP), the OCSP responder, the TSA and the trusted list on and off, one at a time. */
export function FaultsPage({ initial, onChanged }: { initial: SandboxFaults | null; onChanged: (faults: SandboxFaults) => void }) {
  const { t } = useI18n()
  const [faults, setFaults] = useState<SandboxFaults | null>(initial)
  // Fresh on every visit: another app may have switched a failure meanwhile.
  useEffect(() => {
    api.faults().then(setFaults).catch(() => {})
  }, [])
  // PATCH sends only the change: another app switching another failure meanwhile is not undone.
  const apply = async (change: () => Promise<SandboxFaults>, done: string) => {
    try {
      const saved = await change()
      setFaults(saved)
      onChanged(saved)
      toast.success(done)
    } catch (e) {
      toast.error(t("common.error"), { description: (e as Error).message })
    }
  }
  if (!faults) return <p className="text-muted-foreground text-sm">{t("common.loading")}</p>
  const anyOn = rows.some((r) => !r.neutral && (faults[r.field] ?? "None") !== "None")
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted-foreground max-w-3xl text-sm">{t("faults.intro")}</p>
        <Button variant="outline" size="sm" disabled={!anyOn} onClick={() => apply(api.faultsOff, t("faults.allOffDone"))}>
          <PowerOff /> {t("faults.allOff")}
        </Button>
      </div>
      <div className="divide-y rounded-lg border">
        {rows.map((row) => {
          const current = String(faults[row.field] ?? row.values[0])
          const on = !row.neutral && current !== row.values[0]
          return (
            <FaultRow key={row.field} row={row} current={current} on={on} delay={row.delay && current === "Slow" ? faults[row.delay] : null}
              onChoose={(v) => apply(() => api.patchFaults({ [row.field]: v }), t("faults.saved"))}
              onDelay={(ms) => { const field = row.delay; if (field) void apply(() => api.patchFaults({ [field]: ms }), t("faults.saved")) }} />
          )
        })}
      </div>
    </div>
  )
}

function FaultRow({ row, current, on, delay, onChoose, onDelay }: {
  row: Row
  current: string
  on: boolean
  delay: number | null
  onChoose: (value: string) => void
  onDelay: (ms: number) => void
}) {
  const { t } = useI18n()
  const [ms, setMs] = useState(String(delay ?? 3000))
  useEffect(() => setMs(String(delay ?? 3000)), [delay])
  return (
    <div className={cn("grid items-center gap-x-4 gap-y-1.5 px-4 py-3 md:grid-cols-[14rem_16rem_1fr]", on && "bg-destructive/5")}>
      <span className="flex items-center gap-2 text-sm font-medium">
        {t(row.title)}
        {on && <Pill tone="danger">{t("faults.on")}</Pill>}
      </span>
      <Select value={current} onValueChange={onChoose}>
        <SelectTrigger size="sm" className="w-full" aria-label={t(row.title)}><SelectValue /></SelectTrigger>
        <SelectContent position="popper">
          {row.values.map((v) => <SelectItem key={v} value={v}>{t(`${row.prefix}.${v}.title` as MessageKey)}</SelectItem>)}
        </SelectContent>
      </Select>
      <span className="text-muted-foreground flex flex-wrap items-center gap-3 text-xs">
        {t(`${row.prefix}.${current}.hint` as MessageKey)}
        {delay !== null && (
          <label className="text-foreground flex items-center gap-2">
            {t("faults.delay")}
            <Input className="h-8 w-24" type="number" min={0} max={60000} step={500} value={ms} onChange={(e) => setMs(e.target.value)}
              onBlur={() => onDelay(Math.max(0, Math.min(60000, Number(ms) || 0)))} />
          </label>
        )}
      </span>
    </div>
  )
}
