import { useState } from "react"
import { Download, RotateCcw, ShieldX, Undo2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { KeyValue, Pill, Section } from "@/components/parts"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { revocationReasons, type CertificateView, type PkiView, type Publication, type SandboxInfo } from "@/lib/types"

const publications: Publication[] = ["Both", "CrlOnly", "OcspOnly"]

const pointerLabels: Record<string, string> = { CrlHttp: "CRL HTTP", CrlHttps: "CRL HTTPS", CrlLdap: "CRL LDAP", Ocsp: "OCSP" }

/** The CAs, the issued certificates (signers and the services' own), with revocation and downloads. */
export function PkiPage({ info, pki, onChanged }: { info: SandboxInfo; pki: PkiView; onChanged: () => void }) {
  const { t, date } = useI18n()
  const [reason, setReason] = useState<string>("KeyCompromise")
  const [publication, setPublication] = useState<Publication>("Both")
  const [busy, setBusy] = useState(false)
  const run = async (action: () => Promise<unknown>, done: string) => {
    setBusy(true)
    try {
      await action()
      toast.success(done)
      onChanged()
    } catch (e) {
      toast.error(t("common.error"), { description: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }
  const signers = pki.certificates.filter((c) => c.usage === "Signing")
  const services = pki.certificates.filter((c) => c.usage !== "Signing")
  const table = (rows: CertificateView[]) => (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[40%]">{t("pki.subject")}</TableHead>
            <TableHead>{t("pki.validity")}</TableHead>
            <TableHead>{t("pki.status")}</TableHead>
            <TableHead className="text-right" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="whitespace-normal">
                <span className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
                  {c.title}<span className="text-muted-foreground font-mono text-[11px] font-normal">{c.id}</span>
                </span>
                <span className="text-muted-foreground block text-xs">{c.description}</span>
                <span className="mt-1 flex flex-wrap gap-1">
                  {c.issuerId && c.issuerId !== "intermediate" && <Pill tone="warning">{t("pki.issuedBy", { ca: c.issuerId })}</Pill>}
                  {(c.pointers ?? "").split(", ").filter((p) => p && p !== "None").map((p) => <Pill key={p}>{pointerLabels[p] ?? p}</Pill>)}
                </span>
              </TableCell>
              <TableCell className="text-xs tabular-nums">{date(c.notBefore)} → {date(c.notAfter)}</TableCell>
              <TableCell>
                <span className="flex flex-wrap gap-1">
                  {c.revokedAt
                    ? <Pill tone="danger">{t("pki.revoked", { date: date(c.revokedAt) })}{c.revocationReason ? ` · ${c.revocationReason}` : ""}</Pill>
                    : c.problem ? <Pill tone="warning">{c.problem}</Pill> : <Pill tone="success">{t("pki.valid")}</Pill>}
                  {c.revokedAt && c.publication && c.publication !== "Both" && <Pill tone="warning">{t(`pki.publication.${c.publication}` as MessageKey)}</Pill>}
                  {c.keyType && <Pill>{c.keyType}</Pill>}
                </span>
              </TableCell>
              <TableCell className="text-right">
                <span className="inline-flex gap-1">
                  <Button variant="ghost" size="sm" asChild><a href={api.pfxUrl(c.id)}><Download /> PFX</a></Button>
                  <Button variant="ghost" size="sm" asChild><a href={api.cerUrl(c.id)}>.cer</a></Button>
                  {c.revokedAt
                    ? <Button variant="outline" size="sm" disabled={busy} onClick={() => run(() => api.unrevoke(c.id), t("pki.unrevokedToast", { title: c.title }))}><Undo2 /> {t("pki.unrevoke")}</Button>
                    : <Button variant="outline" size="sm" disabled={busy} onClick={() => run(() => api.revoke(c.id, reason, publication), t("pki.revokedToast", { title: c.title }))}><ShieldX /> {t("pki.revoke")}</Button>}
                </span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
  return (
    <div className="space-y-8">
      <Section title={t("pki.authorities")} description={t("pki.authoritiesHint")}>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {pki.authorities.map((view) => (
            <div key={view.id} className="rounded-lg border px-4 py-2">
              <p className="flex items-center justify-between gap-2 py-1 text-sm font-medium">
                {view.title}
                <a href={info.authorities.find((a) => a.id === view.id)?.certificate} className="text-muted-foreground hover:text-foreground" aria-label={t("common.download")}><Download className="size-4" /></a>
              </p>
              <span className="flex flex-wrap gap-1 pb-1">
                {view.revokedAt ? <Pill tone="danger">{t("pki.revoked", { date: date(view.revokedAt) })}</Pill>
                  : view.problem ? <Pill tone="warning">{view.problem}</Pill> : <Pill tone="success">{t("pki.valid")}</Pill>}
              </span>
              <KeyValue stacked label={t("pki.subject")}>{view.subject}</KeyValue>
              <KeyValue label={t("pki.validity")}>{date(view.notBefore)} → {date(view.notAfter)}</KeyValue>
            </div>
          ))}
        </div>
      </Section>

      <Section title={t("pki.certificates")} description={t("pki.certificatesHint", { password: info.pfxPassword })}
        aside={
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">{t("pki.reason")}</span>
            <Select value={reason} onValueChange={setReason}>
              <SelectTrigger size="sm" className="w-44"><SelectValue /></SelectTrigger>
              <SelectContent>{revocationReasons.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
            </Select>
            <span className="text-muted-foreground text-xs">{t("pki.publishedIn")}</span>
            <Select value={publication} onValueChange={(v) => setPublication(v as Publication)}>
              <SelectTrigger size="sm" className="w-40"><SelectValue /></SelectTrigger>
              <SelectContent>{publications.map((p) => <SelectItem key={p} value={p}>{t(`pki.publication.${p}` as MessageKey)}</SelectItem>)}</SelectContent>
            </Select>
            <Button variant="outline" size="sm" disabled={busy} title={t("pki.resetHint")} onClick={() => run(api.reset, t("pki.resetDone"))}>
              <RotateCcw /> {t("pki.reset")}
            </Button>
          </div>
        }>
        {table(signers)}
      </Section>

      <Section title={t("pki.services")} description={t("pki.servicesHint")}>
        {table(services)}
      </Section>
    </div>
  )
}
