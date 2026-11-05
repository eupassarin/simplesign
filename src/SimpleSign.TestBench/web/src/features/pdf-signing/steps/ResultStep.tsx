import { useState } from "react"
import { Check, CheckCircle2, CircleSlash, Copy, Download, FileCheck2, Loader2, TriangleAlert, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api } from "@/lib/api"
import type { SignatureReport, SigningResult } from "@/lib/types"
import { cn } from "@/lib/utils"
import { PdfPreview } from "../PdfPreview"
import { IssueList, KeyValue, Pill } from "../ui"

export function ResultView({ result }: { result: SigningResult }) {
  if (!result.success) {
    return (
      <div className="space-y-4">
        <Alert variant="destructive">
          <XCircle />
          <AlertTitle>The library refused or failed ({result.errorType})</AlertTitle>
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
          <p className="font-medium">Signed: {result.achievedLevel}</p>
          <p className="text-muted-foreground text-xs">
            Requested {result.requestedLevel} · {(result.bytes / 1024).toFixed(1)} KB · signed in {result.signMs} ms{result.validation.length > 0 && `, validated in ${result.validateMs} ms`}
          </p>
        </div>
        {mine && <Indication value={mine.indication} />}
        <Button asChild>
          <a href={api.fileUrl(result.outputId!, true)}><Download /> Download</a>
        </Button>
      </div>
      {result.warnings.length > 0 && (
        <Alert>
          <TriangleAlert />
          <AlertTitle>Warnings</AlertTitle>
          <AlertDescription><ul className="list-disc pl-4">{result.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul></AlertDescription>
        </Alert>
      )}
      <Tabs defaultValue="report">
        <TabsList>
          <TabsTrigger value="report">Validation report</TabsTrigger>
          <TabsTrigger value="output">Output</TabsTrigger>
          {result.deferred && <TabsTrigger value="deferred">Deferred</TabsTrigger>}
          {result.batch.length > 0 && <TabsTrigger value="batch">Batch</TabsTrigger>}
          <TabsTrigger value="code">Code</TabsTrigger>
          <TabsTrigger value="pdf">PDF</TabsTrigger>
        </TabsList>
        <TabsContent value="report" className="space-y-4 pt-4">
          {result.validation.length === 0 && <p className="text-muted-foreground text-sm">Validation was turned off.</p>}
          {result.validation.map((v, i) => <SignatureCard key={i} report={v} />)}
        </TabsContent>
        <TabsContent value="output" className="pt-4">
          <div className="grid gap-x-8 rounded-lg border p-4 sm:grid-cols-2">
            <KeyValue label="Signatures in the file">{result.output?.signatureCount}</KeyValue>
            <KeyValue label="Detected PAdES level">{result.output?.detectedLevel}</KeyValue>
            <KeyValue label="Signature timestamp">{yes(result.hasSignatureTimestamp)}</KeyValue>
            <KeyValue label="LTV material (DSS)">{result.output?.hasDss ? `${result.output.dssCertificates} certs, ${result.output.dssCrls} CRLs, ${result.output.dssOcsps} OCSPs` : "no"}</KeyValue>
            <KeyValue label="Archive (document) timestamp">{yes(result.hasArchiveTimestamp)}</KeyValue>
            <KeyValue label="DocMDP">{result.output?.docMdpLevel ? `P=${result.output.docMdpLevel}` : "none"}</KeyValue>
            <KeyValue label="PDF/A">{result.output?.pdfALevel}</KeyValue>
          </div>
        </TabsContent>
        {result.deferred && (
          <TabsContent value="deferred" className="pt-4">
            <div className="space-y-1 rounded-lg border p-4">
              <KeyValue label="HashToSign (DER signed attributes)" mono>{result.deferred.hashToSignHex}</KeyValue>
              <KeyValue label="Digest algorithm">{result.deferred.digestAlgorithm}</KeyValue>
              <KeyValue label="Signature algorithm OID" mono>{result.deferred.signatureAlgorithmOid}</KeyValue>
              <KeyValue label="Session (sealed, no secrets)">{result.deferred.sessionBytes} bytes</KeyValue>
              <KeyValue label="Raw signature returned by the signer" mono>{result.deferred.rawSignatureHex}</KeyValue>
            </div>
          </TabsContent>
        )}
        {result.batch.length > 0 && (
          <TabsContent value="batch" className="pt-4">
            <Table>
              <TableHeader><TableRow><TableHead>Id</TableHead><TableHead>Result</TableHead><TableHead className="text-right">Size</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {result.batch.map((b) => (
                  <TableRow key={b.id}>
                    <TableCell className="font-mono text-xs">{b.id}</TableCell>
                    <TableCell>{b.ok ? <Pill tone="success">signed</Pill> : <span className="text-destructive text-xs">{b.error}</span>}</TableCell>
                    <TableCell className="text-right text-xs">{(b.bytes / 1024).toFixed(1)} KB</TableCell>
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

const yes = (b: boolean) => (b ? "yes" : "no")

function Indication({ value }: { value: SignatureReport["indication"] }) {
  return value === "Valid" ? <Pill tone="success">Valid</Pill> : value === "Invalid" ? <Pill tone="danger">Invalid</Pill> : <Pill tone="warning">Indeterminate</Pill>
}

function SignatureCard({ report }: { report: SignatureReport }) {
  return (
    <div className="rounded-lg border">
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        <FileCheck2 className="size-4" />
        <span className="font-medium">{report.fieldName}</span>
        {report.isDocumentTimestamp && <Pill tone="info">document timestamp</Pill>}
        <span className="text-muted-foreground text-xs">{report.signer}</span>
        <span className="ml-auto"><Indication value={report.indication} /></span>
      </div>
      <div className="grid gap-x-8 px-4 py-3 sm:grid-cols-2">
        <KeyValue label="Sub-filter" mono>{report.subFilter ?? "—"}</KeyValue>
        <KeyValue label="Digest">{report.digest ?? "—"}</KeyValue>
        <KeyValue label="Signing time">{report.signingTime ?? "—"}</KeyValue>
        {report.policyLevel && <KeyValue label="Policy level">{report.policyLevel}</KeyValue>}
        {report.signerId && <KeyValue label="Signer id">{report.signerId}</KeyValue>}
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
  return (
    <div className="relative">
      <pre className="bg-muted/50 max-h-[520px] overflow-auto rounded-lg border p-4 font-mono text-xs leading-relaxed">{code}</pre>
      <Button variant="outline" size="sm" className="absolute top-2 right-2 h-7"
        onClick={() => {
          navigator.clipboard.writeText(code)
          setCopied(true)
          toast.success("Copied")
          setTimeout(() => setCopied(false), 1500)
        }}>
        {copied ? <Check /> : <Copy />}
      </Button>
    </div>
  )
}

export function SigningSpinner() {
  return (
    <div className={cn("text-muted-foreground flex items-center gap-2 py-10 text-sm")}>
      <Loader2 className="size-4 animate-spin" /> Signing and validating…
    </div>
  )
}
