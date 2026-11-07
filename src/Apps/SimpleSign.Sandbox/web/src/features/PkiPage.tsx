import { useState } from "react"
import { Download, RotateCcw, ShieldCheck, ShieldX, Undo2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { KeyValue, Pill, Section } from "@/components/parts"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { revocationReasons, type CertificateView, type PkiView, type SandboxInfo } from "@/lib/types"

/** The CAs, the TSAs and the issued certificates, with revocation and downloads. */
export function PkiPage({ info, pki, onChanged }: { info: SandboxInfo; pki: PkiView; onChanged: () => void }) {
  const { t, date } = useI18n()
  const [reason, setReason] = useState<string>("KeyCompromise")
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
  const authorities: { view: CertificateView; download: string }[] = [
    { view: pki.root, download: info.urls.rootCertificate },
    { view: pki.intermediate, download: info.urls.intermediateCertificate },
    { view: pki.tsa, download: "" },
    { view: pki.untrustedTsa, download: "" },
  ]
  return (
    <div className="space-y-8">
      <Section title={t("pki.authorities")}>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {authorities.map(({ view, download }) => (
            <div key={view.id} className="rounded-lg border px-4 py-2">
              <p className="flex items-center justify-between gap-2 py-1 text-sm font-medium">
                {view.title}
                {download && <a href={download} className="text-muted-foreground hover:text-foreground" aria-label={t("common.download")}><Download className="size-4" /></a>}
              </p>
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
              <SelectTrigger size="sm" className="w-48"><SelectValue /></SelectTrigger>
              <SelectContent>{revocationReasons.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
            </Select>
            <Button variant="outline" size="sm" disabled={busy} title={t("pki.resetHint")} onClick={() => run(api.reset, t("pki.resetDone"))}>
              <RotateCcw /> {t("pki.reset")}
            </Button>
          </div>
        }>
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[38%]">{t("pki.subject")}</TableHead>
                <TableHead>{t("pki.validity")}</TableHead>
                <TableHead>{t("pki.status")}</TableHead>
                <TableHead className="text-right" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {pki.certificates.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="whitespace-normal">
                    <span className="flex flex-wrap items-center gap-1.5 text-sm font-medium">{c.title}<span className="text-muted-foreground font-mono text-[11px] font-normal">{c.id}</span></span>
                    <span className="text-muted-foreground block text-xs">{c.description}</span>
                  </TableCell>
                  <TableCell className="text-xs tabular-nums">{date(c.notBefore)} → {date(c.notAfter)}</TableCell>
                  <TableCell>
                    <span className="flex flex-wrap gap-1">
                      {c.revokedAt
                        ? <Pill tone="danger">{t("pki.revoked", { date: date(c.revokedAt) })}{c.revocationReason ? ` · ${c.revocationReason}` : ""}</Pill>
                        : c.problem ? <Pill tone="warning">{c.problem}</Pill> : <Pill tone="success">{t("pki.valid")}</Pill>}
                      {c.keyType && <Pill>{c.keyType}</Pill>}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <span className="inline-flex gap-1">
                      <Button variant="ghost" size="sm" asChild><a href={api.pfxUrl(c.id)}><Download /> PFX</a></Button>
                      <Button variant="ghost" size="sm" asChild><a href={api.cerUrl(c.id)}>.cer</a></Button>
                      {c.revokedAt
                        ? <Button variant="outline" size="sm" disabled={busy} onClick={() => run(() => api.unrevoke(c.id), t("pki.unrevokedToast", { title: c.title }))}><Undo2 /> {t("pki.unrevoke")}</Button>
                        : <Button variant="outline" size="sm" disabled={busy} onClick={() => run(() => api.revoke(c.id, reason), t("pki.revokedToast", { title: c.title }))}><ShieldX /> {t("pki.revoke")}</Button>}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className="text-muted-foreground flex items-center gap-1.5 text-xs"><ShieldCheck className="size-3.5" /> {info.urls.intermediateCrl}</p>
      </Section>
    </div>
  )
}
