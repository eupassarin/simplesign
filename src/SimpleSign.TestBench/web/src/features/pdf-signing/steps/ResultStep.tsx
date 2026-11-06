import { useState } from "react"
import { Check, CheckCircle2, CircleSlash, Copy, Download, FileCheck2, Loader2, TriangleAlert, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, useT } from "@/i18n"
import { api } from "@/lib/api"
import type { SignatureReport, SigningResult } from "@/lib/types"
import { cn } from "@/lib/utils"
import { PdfPreview } from "../PdfPreview"
import { IssueList, KeyValue, Pill } from "../ui"

export function ResultView({ result }: { result: SigningResult }) {
  const { t, number } = useI18n()
  const yes = (b: boolean) => t(b ? "common.yes" : "common.no")
  if (!result.success) {
    return (
      <div className="space-y-4">
        <Alert variant="destructive">
          <XCircle />
          <AlertTitle>{t("result.failed", { type: result.errorType ?? "" })}</AlertTitle>
          <AlertDescription className="break-words">{result.error}</AlertDescription>
        </Alert>
        <IssueList issues={result.issues} />
        {result.code.cSharp && <CodeTabs result={result} />}
      </div>
    )
  }
  const mine = result.validation.filter((v) => !v.isDocumentTimestamp).at(-1)
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center gap-3 rounded-lg border p-4">
        <CheckCircle2 className="text-success size-6" />
        <div className="min-w-0 flex-1">
          <p className="font-medium">{t("result.signed", { level: result.achievedLevel ?? "" })}</p>
          <p className="text-muted-foreground text-xs">
            {t("result.summary", { level: result.requestedLevel, size: number(result.bytes / 1024, 1), ms: result.signMs })}
            {result.validation.length > 0 && t("result.validatedIn", { ms: result.validateMs })}
          </p>
        </div>
        {mine && <Indication value={mine.indication} />}
        <Button asChild>
          <a href={api.fileUrl(result.outputId!, true)}><Download /> {t("common.download")}</a>
        </Button>
      </div>
      {result.warnings.length > 0 && (
        <Alert>
          <TriangleAlert />
          <AlertTitle>{t("result.warnings")}</AlertTitle>
          <AlertDescription><ul className="list-disc pl-4">{result.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul></AlertDescription>
        </Alert>
      )}
      <Tabs defaultValue="report">
        <TabsList>
          <TabsTrigger value="report">{t("result.tabs.report")}</TabsTrigger>
          <TabsTrigger value="output">{t("result.tabs.output")}</TabsTrigger>
          {result.deferred && <TabsTrigger value="deferred">{t("result.tabs.deferred")}</TabsTrigger>}
          {result.batch.length > 0 && <TabsTrigger value="batch">{t("result.tabs.batch")}</TabsTrigger>}
          <TabsTrigger value="code">{t("result.tabs.code")}</TabsTrigger>
          <TabsTrigger value="pdf">PDF</TabsTrigger>
        </TabsList>
        <TabsContent value="report" className="space-y-4 pt-4">
          {result.validation.length === 0 && <p className="text-muted-foreground text-sm">{t("result.validationOff")}</p>}
          {result.validation.map((v, i) => <SignatureCard key={i} report={v} />)}
        </TabsContent>
        <TabsContent value="output" className="pt-4">
          <div className="grid gap-x-8 rounded-lg border p-4 sm:grid-cols-2">
            <KeyValue label={t("result.output.signatures")}>{result.output?.signatureCount}</KeyValue>
            <KeyValue label={t("result.output.level")}>{result.output?.detectedLevel}</KeyValue>
            <KeyValue label={t("result.output.timestamp")}>{yes(result.hasSignatureTimestamp)}</KeyValue>
            <KeyValue label={t("result.output.dss")}>{result.output?.hasDss ? t("result.output.dssValue", { certs: result.output.dssCertificates, crls: result.output.dssCrls, ocsps: result.output.dssOcsps }) : t("common.no")}</KeyValue>
            <KeyValue label={t("result.output.archive")}>{yes(result.hasArchiveTimestamp)}</KeyValue>
            <KeyValue label="DocMDP">{result.output?.docMdpLevel ? `P=${result.output.docMdpLevel}` : t("common.none")}</KeyValue>
            <KeyValue label="PDF/A">{result.output?.pdfALevel}</KeyValue>
          </div>
        </TabsContent>
        {result.deferred && (
          <TabsContent value="deferred" className="pt-4">
            <div className="space-y-1 rounded-lg border p-4">
              <KeyValue label={t("result.deferred.hashToSign")} mono>{result.deferred.hashToSignHex}</KeyValue>
              <KeyValue label={t("result.deferred.digest")}>{result.deferred.digestAlgorithm}</KeyValue>
              <KeyValue label={t("result.deferred.algorithm")} mono>{result.deferred.signatureAlgorithmOid}</KeyValue>
              <KeyValue label={t("result.deferred.session")}>{t("result.deferred.bytes", { n: result.deferred.sessionBytes })}</KeyValue>
              <KeyValue label={t("result.deferred.raw")} mono>{result.deferred.rawSignatureHex}</KeyValue>
            </div>
          </TabsContent>
        )}
        {result.batch.length > 0 && (
          <TabsContent value="batch" className="pt-4">
            <Table>
              <TableHeader><TableRow><TableHead>Id</TableHead><TableHead>{t("result.batch.result")}</TableHead><TableHead className="text-right">{t("result.batch.size")}</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {result.batch.map((b) => (
                  <TableRow key={b.id}>
                    <TableCell className="font-mono text-xs">{b.id}</TableCell>
                    <TableCell>{b.ok ? <Pill tone="success">{t("result.batch.signed")}</Pill> : <span className="text-destructive text-xs">{b.error}</span>}</TableCell>
                    <TableCell className="text-right text-xs">{number(b.bytes / 1024, 1)} KB</TableCell>
                    <TableCell className="text-right">{b.outputId && <Button variant="ghost" size="sm" asChild><a href={api.fileUrl(b.outputId, true)}><Download /></a></Button>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TabsContent>
        )}
        <TabsContent value="code" className="pt-4"><CodeTabs result={result} /></TabsContent>
        <TabsContent value="pdf" className="pt-4"><PdfPreview url={api.fileUrl(result.outputId!)} page={1} onPageChange={() => {}} /></TabsContent>
      </Tabs>
    </div>
  )
}


function Indication({ value }: { value: SignatureReport["indication"] }) {
  const t = useT()
  return value === "Valid" ? <Pill tone="success">{t("result.indication.Valid")}</Pill> : value === "Invalid" ? <Pill tone="danger">{t("result.indication.Invalid")}</Pill> : <Pill tone="warning">{t("result.indication.Indeterminate")}</Pill>
}

function SignatureCard({ report }: { report: SignatureReport }) {
  const t = useT()
  return (
    <div className="rounded-lg border">
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        <FileCheck2 className="size-4" />
        <span className="font-medium">{report.fieldName}</span>
        {report.isDocumentTimestamp && <Pill tone="info">{t("result.report.docTimestamp")}</Pill>}
        <span className="text-muted-foreground text-xs">{report.signer}</span>
        <span className="ml-auto"><Indication value={report.indication} /></span>
      </div>
      <div className="grid gap-x-8 px-4 py-3 sm:grid-cols-2">
        <KeyValue label="Sub-filter" mono>{report.subFilter ?? "—"}</KeyValue>
        <KeyValue label={t("result.report.digest")}>{report.digest ?? "—"}</KeyValue>
        <KeyValue label={t("result.report.signingTime")}>{report.signingTime ?? "—"}</KeyValue>
        {report.policyLevel && <KeyValue label={t("result.report.policyLevel")}>{report.policyLevel}</KeyValue>}
        {report.signerId && <KeyValue label={t("result.report.signerId")}>{report.signerId}</KeyValue>}
      </div>
      <ul className="divide-y border-t">
        {report.checks.map((c) => (
          <li key={c.name} className="flex items-start gap-2 px-4 py-2 text-sm">
            {c.status === "pass" ? <Check className="text-success mt-0.5 size-4" /> : c.status === "fail" ? <XCircle className="text-destructive mt-0.5 size-4" /> : c.status === "warn" ? <TriangleAlert className="text-warning mt-0.5 size-4" /> : <CircleSlash className="text-muted-foreground mt-0.5 size-4" />}
            <span className="flex-1">{c.name}</span>
            <span className="text-muted-foreground max-w-[50%] text-right text-xs">{c.detail}</span>
          </li>
        ))}
      </ul>
      {(report.errors.length > 0 || report.warnings.length > 0) && (
        <ul className="space-y-1 border-t px-4 py-3 text-xs">
          {report.errors.map((e, i) => <li key={`e${i}`} className="text-destructive">✕ {e}</li>)}
          {report.warnings.map((w, i) => <li key={`w${i}`} className="text-muted-foreground">! {w}</li>)}
        </ul>
      )}
      {report.metadata && Object.keys(report.metadata).length > 0 && (
        <div className="grid gap-x-8 border-t px-4 py-3 sm:grid-cols-2">
          {Object.entries(report.metadata).map(([k, v]) => <KeyValue key={k} label={k}>{v}</KeyValue>)}
        </div>
      )}
    </div>
  )
}

export function CodeTabs({ result }: { result: SigningResult }) {
  return (
    <Tabs defaultValue="csharp">
      <TabsList>
        <TabsTrigger value="csharp">C#</TabsTrigger>
        <TabsTrigger value="cli">CLI</TabsTrigger>
      </TabsList>
      <TabsContent value="csharp" className="pt-3"><CodeBlock code={result.code.cSharp} /></TabsContent>
      <TabsContent value="cli" className="space-y-3 pt-3">
        <CodeBlock code={result.code.cli} />
        {result.code.cliNotes.length > 0 && <ul className="text-muted-foreground space-y-1 text-xs">{result.code.cliNotes.map((n, i) => <li key={i}>• {n}</li>)}</ul>}
      </TabsContent>
    </Tabs>
  )
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)
  const t = useT()
  return (
    <div className="relative">
      <pre className="bg-muted/50 max-h-[520px] overflow-auto rounded-lg border p-4 font-mono text-xs leading-relaxed">{code}</pre>
      <Button variant="outline" size="sm" className="absolute top-2 right-2 h-7"
        onClick={() => {
          navigator.clipboard.writeText(code)
          setCopied(true)
          toast.success(t("common.copied"))
          setTimeout(() => setCopied(false), 1500)
        }}>
        {copied ? <Check /> : <Copy />}
      </Button>
    </div>
  )
}

export function SigningSpinner() {
  const t = useT()
  return (
    <div className={cn("text-muted-foreground flex items-center gap-2 py-10 text-sm")}>
      <Loader2 className="size-4 animate-spin" /> {t("result.signing")}
    </div>
  )
}
