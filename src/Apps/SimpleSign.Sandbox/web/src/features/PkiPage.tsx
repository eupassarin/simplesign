import { useState } from "react"
import { Download, RotateCcw, ShieldX, Undo2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Fold, KeyValue, Pill, Section } from "@/components/parts"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { revocationReasons, type CertificateView, type PkiView, type Publication, type SandboxInfo } from "@/lib/types"

const publications: Publication[] = ["Both", "CrlOnly", "OcspOnly"]

const pointerLabels: Record<string, string> = { CrlHttp: "CRL HTTP", CrlHttps: "CRL HTTPS", CrlLdap: "CRL LDAP", Ocsp: "OCSP" }

/** The CAs, the issued certificates (signers and the services' own), with revocation and downloads. */
export function PkiPage({ info, pki, onChanged }: { info: SandboxInfo; pki: PkiView; onChanged: () => void }) {
  const { t, date } = useI18n()
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
  const status = (c: CertificateView) => c.revokedAt
    ? <Pill tone="danger">{t("pki.revoked", { date: date(c.revokedAt) })}{c.revocationReason ? ` · ${c.revocationReason}` : ""}</Pill>
    : c.problem ? <Pill tone="warning">{c.problem}</Pill> : <Pill tone="success">{t("pki.valid")}</Pill>
  const signers = pki.certificates.filter((c) => c.usage === "Signing")
  const services = pki.certificates.filter((c) => c.usage !== "Signing")
  const table = (rows: CertificateView[]) => (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[45%]">{t("pki.subject")}</TableHead>
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
                  {c.issuerId && c.issuerId !== "intermediate" && <Pill tone="warning">{t("pki.issuedBy", { ca: c.issuerId })}</Pill>}
                  {(c.pointers ?? "").split(", ").filter((p) => p && p !== "None").map((p) => <Pill key={p}>{pointerLabels[p] ?? p}</Pill>)}
                </span>
                {c.description && <span className="text-muted-foreground block text-xs">{c.description}</span>}
              </TableCell>
              <TableCell className="text-xs whitespace-nowrap tabular-nums">{date(c.notBefore)} → {date(c.notAfter)}</TableCell>
              <TableCell>
                <span className="flex flex-wrap gap-1">
                  {status(c)}
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
                    : <RevokeButton disabled={busy} onRevoke={(reason, publication) => run(() => api.revoke(c.id, reason, publication), t("pki.revokedToast", { title: c.title }))} />}
                </span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
  return (
    <div className="space-y-6">
      <Section title={t("pki.authorities")} description={t("pki.authoritiesHint")}>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {pki.authorities.map((view) => (
            <Fold key={view.id} id={`pki.ca.${view.id}`} title={<span className="flex flex-wrap items-center gap-2">{view.title} {status(view)}</span>}
              aside={<a href={info.authorities.find((a) => a.id === view.id)?.certificate} className="text-muted-foreground hover:text-foreground" aria-label={t("common.download")}><Download className="size-4" /></a>}>
              <KeyValue stacked label={t("pki.subject")}>{view.subject}</KeyValue>
              <KeyValue label={t("pki.validity")}>{date(view.notBefore)} → {date(view.notAfter)}</KeyValue>
            </Fold>
          ))}
        </div>
      </Section>

      <Section title={t("pki.certificates")} description={t("pki.certificatesHint", { password: info.pfxPassword })}
        aside={
          <Button variant="outline" size="sm" disabled={busy} title={t("pki.resetHint")} onClick={() => run(api.reset, t("pki.resetDone"))}>
            <RotateCcw /> {t("pki.reset")}
          </Button>
        }>
        {table(signers)}
      </Section>

      <Fold id="pki.services" title={t("pki.services")} summary={t("pki.servicesSummary", { n: services.length })}>
        <p className="text-muted-foreground py-1 text-xs">{t("pki.servicesHint")}</p>
        <div className="py-1.5">{table(services)}</div>
      </Fold>
    </div>
  )
}

/** Revoke, after choosing the reason and where the revocation is published (CRL, OCSP or both). */
function RevokeButton({ disabled, onRevoke }: { disabled: boolean; onRevoke: (reason: string, publication: Publication) => void }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState<string>("KeyCompromise")
  const [publication, setPublication] = useState<Publication>("Both")
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" disabled={disabled}><ShieldX /> {t("pki.revoke")}</Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-64 space-y-3">
        <div className="space-y-1.5">
          <Label className="text-xs">{t("pki.reason")}</Label>
          <Select value={reason} onValueChange={setReason}>
            <SelectTrigger size="sm" className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent position="popper">{revocationReasons.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("pki.publishedIn")}</Label>
          <Select value={publication} onValueChange={(v) => setPublication(v as Publication)}>
            <SelectTrigger size="sm" className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent position="popper">{publications.map((p) => <SelectItem key={p} value={p}>{t(`pki.publication.${p}` as MessageKey)}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <Button size="sm" variant="destructive" className="w-full" onClick={() => { setOpen(false); onRevoke(reason, publication) }}>
          <ShieldX /> {t("pki.revokeConfirm")}
        </Button>
      </PopoverContent>
    </Popover>
  )
}
