import { useEffect, useState } from "react"
import { Download, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { CertificateView, DetailedSignature, InspectionReport } from "@/lib/types"
import { SignatureCard } from "../shared/results"
import { KeyValue, Pill } from "../shared/ui"

// What a PDF signature holds, as the validator and the inspector read it: the detailed card of
// one signature, and the dump of the signature objects.

export function DetailedCard({ signature: s }: { signature: DetailedSignature }) {
  const { t } = useI18n()
  return (
    <div className="space-y-3">
      <SignatureCard report={s.report} />
      <div className="flex flex-wrap gap-1.5">
        {s.padesLevel && <Pill tone="info">PAdES {s.padesLevel.replace("Baseline", "B-").replace("B-LTA", "B-LTA")}</Pill>}
        {s.lei14063Level && <Pill tone="success">{t("validation.lei", { level: s.lei14063Level })}</Pill>}
        {s.policyName && <Pill>{s.policyName}</Pill>}
        {s.deprecatedAlgorithm && <Pill tone="warning">{t("validation.deprecated")}</Pill>}
      </div>
      <Accordion type="multiple" className="rounded-lg border px-4">
        {s.signer && (
          <AccordionItem value="certificate">
            <AccordionTrigger>{t("validation.sections.certificate")}</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <CertificateBlock cert={s.signer} />
              {s.embeddedCertificates.length > 0 && (
                <div className="space-y-1">
                  <p className="text-muted-foreground text-xs font-medium">{t("validation.embedded", { n: s.embeddedCertificates.length })}</p>
                  <ul className="space-y-1 text-xs">{s.embeddedCertificates.map((c) => <li key={c.thumbprint} className="truncate font-mono">• {c.subject}</li>)}</ul>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>
        )}
        {s.timestamp && (
          <AccordionItem value="timestamp">
            <AccordionTrigger>{t("validation.sections.timestamp")}</AccordionTrigger>
            <AccordionContent className="grid gap-x-8 sm:grid-cols-2">
              <KeyValue label={t("validation.timestamp.time")}>{s.timestamp.time}</KeyValue>
              <KeyValue stacked label="TSA">{s.timestamp.tsa ?? "—"}</KeyValue>
              <KeyValue stacked label={t("validation.timestamp.policy")} mono>{s.timestamp.policyOid ?? "—"}</KeyValue>
              <KeyValue label={t("validation.timestamp.hash")}>{s.timestamp.hashAlgorithm ?? "—"}</KeyValue>
            </AccordionContent>
          </AccordionItem>
        )}
        {s.coverage && (
          <AccordionItem value="coverage">
            <AccordionTrigger>{t("validation.sections.coverage")}</AccordionTrigger>
            <AccordionContent className="space-y-2 text-sm">
              <KeyValue label={t("validation.coverage.signedUntil")}>{s.coverage.signedUntil} / {s.coverage.fileSize} bytes</KeyValue>
              <KeyValue label={t("validation.coverage.revision")}>{s.coverage.revision} / {s.coverage.revisions}</KeyValue>
              <p className="text-muted-foreground text-xs">{t(s.coverage.coversWholeFile ? "validation.coverage.whole" : "validation.coverage.later")}</p>
            </AccordionContent>
          </AccordionItem>
        )}
        <AccordionItem value="attributes">
          <AccordionTrigger>{t("validation.sections.attributes")}</AccordionTrigger>
          <AccordionContent className="grid gap-x-8 sm:grid-cols-2">
            <KeyValue label={t("validation.attributes.algorithm")}>{s.signatureAlgorithm ?? "—"}</KeyValue>
            <KeyValue stacked label={t("validation.attributes.policy")} mono>{s.policyOid ?? "—"}</KeyValue>
            <KeyValue stacked label={t("validation.attributes.commitment")} mono>{s.commitmentTypeOid ?? "—"}</KeyValue>
            <KeyValue label={t("details.reason")}>{s.reason ?? "—"}</KeyValue>
            <KeyValue label={t("details.location")}>{s.location ?? "—"}</KeyValue>
            <KeyValue label={t("details.contact")}>{s.contactInfo ?? "—"}</KeyValue>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  )
}

function CertificateBlock({ cert }: { cert: CertificateView }) {
  const { t } = useI18n()
  return (
    <div className="grid gap-x-8 sm:grid-cols-2">
      <KeyValue stacked label={t("validation.cert.subject")}>{cert.subject}</KeyValue>
      <KeyValue stacked label={t("signer.card.issuer")}>{cert.issuer}</KeyValue>
      <KeyValue label={t("signer.card.valid")}>{cert.notBefore} → {cert.notAfter}</KeyValue>
      <KeyValue label={t("signer.card.key")}>{cert.keyAlgorithm} {cert.keySize ?? ""}</KeyValue>
      <KeyValue stacked label={t("validation.cert.serial")} mono>{cert.serialNumber}</KeyValue>
      <KeyValue label="nonRepudiation">{t(cert.hasNonRepudiation ? "common.yes" : "common.no")}</KeyValue>
    </div>
  )
}

export function InspectView({ file }: { file: { id: string } }) {
  const { t } = useI18n()
  const [report, setReport] = useState<InspectionReport | null>(null)
  useEffect(() => {
    setReport(null)
    api.validation.inspect(file.id).then(setReport).catch((e: Error) => toast.error(e.message))
  }, [file.id])
  if (!report) return <Loader2 className="size-5 animate-spin" />
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill>{t("validation.inspect.revisions", { n: report.revisions })}</Pill>
        <Pill>{t("validation.inspect.objects", { n: report.objects.length })}</Pill>
        {report.signatureFields.map((f) => (
          <Button key={f} variant="outline" size="sm" asChild><a href={api.validation.cmsUrl(file.id, f)}><Download /> {t("validation.inspect.cms", { field: f })}</a></Button>
        ))}
      </div>
      <p className="text-muted-foreground text-xs">{t("validation.inspect.hint")}</p>
      {report.error && <Alert variant="destructive"><AlertDescription>{report.error}</AlertDescription></Alert>}
      <Accordion type="multiple" className="rounded-lg border px-4">
        {report.objects.map((o) => (
          <AccordionItem key={o.objectNumber} value={String(o.objectNumber)}>
            <AccordionTrigger>
              <span className="flex flex-wrap items-center gap-2 text-left">
                <span className="text-muted-foreground font-mono text-xs">#{o.objectNumber}</span>
                <span>{o.label}</span>
                {o.badges.map((b) => <Pill key={b}>{b}</Pill>)}
              </span>
            </AccordionTrigger>
            <AccordionContent className="space-y-2">
              {o.streamInfo && <p className="text-muted-foreground text-xs">{t("validation.inspect.stream", { info: o.streamInfo })}</p>}
              {o.cmsContentType && <p className="text-xs">CMS: {o.cmsContentType}{o.cmsSigner ? ` · ${o.cmsSigner}` : ""}</p>}
              <Table>
                <TableBody>
                  {o.entries.map((e, i) => (
                    <TableRow key={i}>
                      <TableCell className="w-40 align-top font-mono text-xs">{e.key}</TableCell>
                      <TableCell className="max-w-md align-top font-mono text-xs break-all whitespace-normal">{e.value}</TableCell>
                      <TableCell className="text-muted-foreground align-top text-xs whitespace-normal">{e.explanation}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  )
}
