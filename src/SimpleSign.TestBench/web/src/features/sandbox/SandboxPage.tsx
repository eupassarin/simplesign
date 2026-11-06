import { useEffect, useState } from "react"
import { Clock, Cloud, KeyRound, RefreshCw, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { SandboxRequest } from "@/lib/types"
import { KeyValue, Pill, Section } from "../pdf-signing/ui"
import { useSigning } from "../pdf-signing/state"

export function SandboxPage() {
  const { env } = useSigning()
  const [log, setLog] = useState<SandboxRequest[]>([])
  const { t, time } = useI18n()
  const load = () => api.sandboxLog().then(setLog)
  useEffect(() => {
    load()
  }, [])
  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="mx-auto max-w-6xl space-y-8 p-6 lg:p-8">
        <header className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">Sandbox</h2>
          <p className="text-muted-foreground max-w-3xl text-sm">
            {t("sandbox.intro")}
          </p>
        </header>
        <Section title={t("sandbox.pki")} description={t("sandbox.pkiHint")}>
          <Table>
            <TableHeader><TableRow><TableHead>{t("sandbox.signer")}</TableHead><TableHead>{t("sandbox.key")}</TableHead><TableHead>{t("sandbox.validUntil")}</TableHead><TableHead>{t("sandbox.shows")}</TableHead></TableRow></TableHeader>
            <TableBody>
              {env?.signers.map((s) => (
                <TableRow key={s.id}>
                  <TableCell><span className="flex items-center gap-2"><KeyRound className="size-3.5" />{s.title}</span></TableCell>
                  <TableCell className="text-xs">{s.keyType}</TableCell>
                  <TableCell className="text-xs">{s.notAfter}</TableCell>
                  <TableCell className="text-muted-foreground max-w-md text-xs whitespace-normal">{s.problem && <Pill tone="warning">{s.problem}</Pill>} {s.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Section>
        <div className="grid gap-4 md:grid-cols-3">
          <Service icon={<Clock className="size-4" />} title={t("sandbox.tsa")}>
            <KeyValue label="URL" mono>{env?.tsaUrl}</KeyValue>
            <KeyValue label={t("sandbox.withBasic")} mono>{env?.authenticatedTsaUrl}</KeyValue>
            <KeyValue label={t("sandbox.userPassword")} mono>{env?.tsaUser} / {env?.tsaPassword}</KeyValue>
          </Service>
          <Service icon={<Cloud className="size-4" />} title="PSC (DOC-ICP-17.01)">
            <KeyValue label="URL" mono>{env?.pscUrl}</KeyValue>
            <KeyValue label="CPF / OTP" mono>{env?.pscCpf} / {env?.pscOtp}</KeyValue>
            <KeyValue label={t("sandbox.client")} mono>testbench</KeyValue>
          </Service>
          <Service icon={<Cloud className="size-4" />} title="CSC API v2">
            <KeyValue label="URL" mono>{env?.cscUrl}</KeyValue>
            <KeyValue label="PIN / OTP" mono>{env?.cscPin} / {env?.cscOtp}</KeyValue>
            <KeyValue label={t("sandbox.credentials")}>{env?.cscCredentials.map((c) => c.id).join(", ")}</KeyValue>
          </Service>
        </div>
        <Section title={t("sandbox.log")} description={t("sandbox.logHint")} aside={<Button variant="outline" size="sm" onClick={load}><RefreshCw /> {t("common.refresh")}</Button>}>
          <div className="rounded-lg border">
            <Table>
              <TableHeader><TableRow><TableHead>{t("sandbox.time")}</TableHead><TableHead>{t("sandbox.service")}</TableHead><TableHead>{t("sandbox.request")}</TableHead><TableHead className="text-right">{t("sandbox.status")}</TableHead></TableRow></TableHeader>
              <TableBody>
                {log.length === 0 && <TableRow><TableCell colSpan={4} className="text-muted-foreground text-center text-xs">{t("sandbox.noRequests")}</TableCell></TableRow>}
                {log.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-xs whitespace-nowrap">{time(r.time)}</TableCell>
                    <TableCell><Pill tone={r.service === "Blocked" ? "danger" : "default"}>{r.service}</Pill></TableCell>
                    <TableCell className="max-w-xl truncate font-mono text-xs">{r.method} {r.url}</TableCell>
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

function Service({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2 rounded-lg border p-4">
      <p className="flex items-center gap-2 text-sm font-medium">{icon} {title}</p>
      <div className="divide-y">{children}</div>
    </div>
  )
}
