import { useEffect, useState } from "react"
import { Clock, Cloud, CornerDownRight, Download, KeyRound, RefreshCw, RotateCcw, ShieldCheck, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { SandboxRequest } from "@/lib/types"
import { cn } from "@/lib/utils"
import { KeyValue, Pill, Section } from "../shared/ui"
import type { CrlFault, SandboxCertificate, SandboxFaults, TsaFault } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"

const tsaFaults: TsaFault[] = ["None", "Down", "Slow", "InvalidToken", "Untrusted"]
const crlFaults: CrlFault[] = ["None", "Down", "Expired"]

/**
 * The sandbox as a lab: its PKI (with downloads), the failures that can be switched on to see
 * how signing and validation react, its services, and the requests they answered.
 */
export function SandboxPage() {
  const { env, sandbox, setSandbox, signWithSandbox, dssStatus, checkDss } = useWorkbench()
  const [log, setLog] = useState<SandboxRequest[]>([])
  const [service, setService] = useState("")
  const { t, time } = useI18n()
  // The traffic is live while the panel is open.
  useEffect(() => {
    const load = () => api.sandboxLog().then(setLog).catch(() => {})
    load()
    api.sandbox.state().then(setSandbox).catch(() => {})
    void checkDss()
    const timer = setInterval(load, 1500)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  if (!sandbox) return null
  const setFaults = (patch: Partial<SandboxFaults>) => api.sandbox.faults({ ...sandbox.faults, ...patch }).then(setSandbox)
  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="space-y-8 p-6 lg:p-8">
        <header className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">{t("lab.title")}</h2>
          <p className="text-muted-foreground max-w-3xl text-sm">{t("sandbox.intro")}</p>
        </header>

        <Section title={t("lab.faults")} description={t("lab.faultsHint")}
          aside={<Button variant="outline" size="sm" disabled={!sandbox.faultsActive} onClick={() => api.sandbox.reset().then(setSandbox)}><RotateCcw /> {t("lab.reset")}</Button>}>
          <div className={cn("grid gap-4 rounded-lg border p-4 md:grid-cols-2", sandbox.faultsActive && "border-warning/60 bg-warning/5")}>
            <div className="space-y-1.5">
              <p className="flex items-center gap-1.5 text-sm font-medium"><Clock className="size-4" /> {t("sandbox.tsa")}</p>
              <div className="flex gap-2">
                <Select value={sandbox.faults.tsa} onValueChange={(v) => setFaults({ tsa: v as TsaFault })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{tsaFaults.map((f) => <SelectItem key={f} value={f}>{t(`lab.tsa.${f}.title` as MessageKey)}</SelectItem>)}</SelectContent>
                </Select>
                {sandbox.faults.tsa === "Slow" && (
                  <Input type="number" className="w-28" min={0} max={60000} step={500} value={sandbox.faults.tsaDelayMs} aria-label="ms"
                    onChange={(e) => setFaults({ tsaDelayMs: Number(e.target.value) })} />
                )}
              </div>
              <p className="text-muted-foreground text-xs leading-relaxed">{t(`lab.tsa.${sandbox.faults.tsa}.hint` as MessageKey)}</p>
            </div>
            <div className="space-y-1.5">
              <p className="flex items-center gap-1.5 text-sm font-medium"><ShieldCheck className="size-4" /> {t("lab.crlServer")}</p>
              <Select value={sandbox.faults.crl} onValueChange={(v) => setFaults({ crl: v as CrlFault })}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>{crlFaults.map((f) => <SelectItem key={f} value={f}>{t(`lab.crl.${f}.title` as MessageKey)}</SelectItem>)}</SelectContent>
              </Select>
              <p className="text-muted-foreground text-xs leading-relaxed">{t(`lab.crl.${sandbox.faults.crl}.hint` as MessageKey)}</p>
            </div>
          </div>
        </Section>

        <Section title={t("sandbox.pki")} description={t("lab.pkiHint")}
          aside={<span className="flex gap-2">
            <Button variant="outline" size="sm" asChild><a href={api.sandbox.rootPemUrl} download="sandbox-root.pem"><Download /> root.pem</a></Button>
            <Button variant="outline" size="sm" asChild><a href={api.sandbox.crlUrl("root")}><Download /> root.crl</a></Button>
            <Button variant="outline" size="sm" asChild><a href={api.sandbox.crlUrl("intermediate")}><Download /> intermediate.crl</a></Button>
          </span>}>
          <ul className="divide-y rounded-lg border">
            <CertificateRow certificate={sandbox.root} depth={0} />
            <CertificateRow certificate={sandbox.intermediate} depth={1} />
            <CertificateRow certificate={sandbox.tsa} depth={2} />
            {sandbox.signers.map((s) => (
              <CertificateRow key={s.id} certificate={s} depth={2}
                actions={<>
                  {s.isUsable && <Button variant="outline" size="sm" className="h-7" onClick={() => signWithSandbox(s.id)}>{t("lab.useSigner")}</Button>}
                  {!s.revokedNow && !s.problem && <Button variant="ghost" size="sm" className="h-7" onClick={() => api.sandbox.revoke(s.id).then(setSandbox)}>{t("lab.revoke")}</Button>}
                </>} />
            ))}
          </ul>
        </Section>

        <div className="grid gap-4 md:grid-cols-2">
          <Service icon={<Clock className="size-4" />} title={t("sandbox.tsa")} onTraffic={() => setService("TSA")}>
            <KeyValue stacked mono label="URL" copy={env?.tsaUrl}>{env?.tsaUrl}</KeyValue>
            <KeyValue stacked mono label={t("sandbox.withBasic")} copy={env?.authenticatedTsaUrl}>{env?.authenticatedTsaUrl}</KeyValue>
            <KeyValue stacked mono label={t("sandbox.userPassword")}>{env?.tsaUser} / {env?.tsaPassword}</KeyValue>
          </Service>
          <Service icon={<ShieldCheck className="size-4" />} title="DSS">
            <KeyValue stacked mono label="URL" copy={dssStatus?.url}>{dssStatus?.url}</KeyValue>
            <KeyValue label={t("sandbox.status")}>{dssStatus ? (dssStatus.reachable ? <Pill tone="success">{t("lab.dssUp", { ms: dssStatus.ms })}</Pill> : <Pill>{t("lab.dssDown")}</Pill>) : "—"}</KeyValue>
            <p className="text-muted-foreground pt-2 text-xs leading-relaxed">{t("lab.dssTrust")}</p>
          </Service>
          <Service icon={<Cloud className="size-4" />} title="PSC (DOC-ICP-17.01)" onTraffic={() => setService("PSC")}>
            <p className="text-muted-foreground pb-2 text-xs leading-relaxed">{t("signer.cloud.psc.what")}</p>
            <KeyValue stacked mono label="URL" copy={env?.pscUrl}>{env?.pscUrl}</KeyValue>
            <KeyValue stacked mono label="CPF / OTP">{env?.pscCpf} / {env?.pscOtp}</KeyValue>
            <KeyValue stacked mono label={t("sandbox.client")}>testbench</KeyValue>
          </Service>
          <Service icon={<Cloud className="size-4" />} title="CSC API v2" onTraffic={() => setService("CSC")}>
            <p className="text-muted-foreground pb-2 text-xs leading-relaxed">{t("signer.cloud.csc.what")}</p>
            <KeyValue stacked mono label="URL" copy={env?.cscUrl}>{env?.cscUrl}</KeyValue>
            <KeyValue stacked mono label="PIN / OTP">{env?.cscPin} / {env?.cscOtp}</KeyValue>
            <KeyValue stacked mono label={t("sandbox.credentials")}>{env?.cscCredentials.map((c) => c.id).join(", ")}</KeyValue>
          </Service>
        </div>

        <Section title={t("sandbox.log")} description={t("sandbox.logHint")} aside={<span className="text-muted-foreground flex items-center gap-1.5 text-xs"><RefreshCw className="size-3 animate-spin [animation-duration:3s]" /> {t("lab.live")}</span>}>
          <div className="flex flex-wrap gap-1.5">
            {["", "TSA", "CRL", "AIA", "PSC", "CSC"].map((name) => (
              <button key={name} type="button" onClick={() => setService(name)}
                className={cn("rounded-full border px-2.5 py-0.5 text-xs", service === name ? "bg-accent border-foreground/30 font-medium" : "text-muted-foreground hover:text-foreground")}>
                {name || t("lab.allServices")} {log.filter((r) => !name || r.service.startsWith(name)).length}
              </button>
            ))}
          </div>
          <div className="rounded-lg border">
            <Table>
              <TableHeader><TableRow><TableHead>{t("sandbox.time")}</TableHead><TableHead>{t("sandbox.service")}</TableHead><TableHead>{t("sandbox.request")}</TableHead><TableHead className="text-right">{t("sandbox.status")}</TableHead></TableRow></TableHeader>
              <TableBody>
                {log.length === 0 && <TableRow><TableCell colSpan={4} className="text-muted-foreground text-center text-xs">{t("sandbox.noRequests")}</TableCell></TableRow>}
                {log.filter((r) => !service || r.service.startsWith(service)).map((r, i) => (
                  <TableRow key={i} className={cn(r.status >= 400 && "bg-warning/5")}>
                    <TableCell className="text-xs whitespace-nowrap">{time(r.time)}</TableCell>
                    <TableCell><Pill tone={r.service === "Blocked" ? "danger" : r.service.includes("fault") ? "warning" : "default"}>{r.service}</Pill></TableCell>
                    <TableCell className="font-mono text-xs break-all whitespace-normal">{r.method} {r.url}</TableCell>
                    <TableCell className="text-right text-xs">{r.status}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Section>
        <p className="text-muted-foreground flex items-center gap-1.5 text-xs"><ShieldCheck className="size-3.5" /> {env?.runtime} · SimpleSign {env?.version} · SHA-3 {t(env?.sha3Supported ? "sandbox.available" : "sandbox.notAvailable")}</p>
      </div>
    </div>
  )
}

/** One certificate of the PKI tree: who it is, its key and validity, and what can be done with it. */
function CertificateRow({ certificate: c, depth, actions }: { certificate: SandboxCertificate; depth: number; actions?: React.ReactNode }) {
  const { t } = useI18n()
  const name = /CN=([^,]+)/.exec(c.subject)?.[1] ?? c.subject
  return (
    <li className={cn("flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2", c.revokedNow && "bg-warning/5")} style={{ paddingLeft: 12 + depth * 22 }}>
      {depth > 0 ? <CornerDownRight className="text-muted-foreground size-3.5 shrink-0" /> : <KeyRound className="size-3.5 shrink-0" />}
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-1.5 text-sm">
          <span className="font-medium">{c.title}</span>
          <span className="text-muted-foreground truncate text-xs">{name}</span>
          {c.problem && <Pill tone="warning">{c.problem}</Pill>}
          {c.revokedNow && <Pill tone="danger"><TriangleAlert className="size-3" /> {t("lab.revokedNow")}</Pill>}
        </span>
        {c.description && <span className="text-muted-foreground block text-xs leading-snug">{c.description}</span>}
      </span>
      <span className="text-muted-foreground shrink-0 text-xs tabular-nums">{c.key} · {c.notBefore} → {c.notAfter}</span>
      <span className="flex shrink-0 items-center gap-1">
        {actions}
        <Button variant="ghost" size="icon" className="size-7" aria-label={`${c.title} .cer`} asChild><a href={api.sandbox.certificateUrl(c.id)}><Download /></a></Button>
      </span>
    </li>
  )
}

function Service({ icon, title, children, onTraffic }: { icon: React.ReactNode; title: string; children: React.ReactNode; onTraffic?: () => void }) {
  const { t } = useI18n()
  return (
    <div className="space-y-2 rounded-lg border p-4">
      <p className="flex items-center gap-2 text-sm font-medium">
        {icon} {title}
        {onTraffic && <button type="button" className="text-muted-foreground hover:text-foreground ml-auto text-xs font-normal underline underline-offset-2" onClick={onTraffic}>{t("lab.seeTraffic")}</button>}
      </p>
      <div className="divide-y">{children}</div>
    </div>
  )
}
