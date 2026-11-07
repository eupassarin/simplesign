import { useState } from "react"
import { Check, CircleSlash, Copy, FileCheck2, Loader2, TriangleAlert, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useT } from "@/i18n"
import type { CodeSnippets, SignatureReport } from "@/lib/types"
import { cn } from "@/lib/utils"
import { KeyValue, Pill } from "./ui"

export function Indication({ value, subIndication }: { value: SignatureReport["indication"]; subIndication?: string | null }) {
  const t = useT()
  const pill = value === "Valid" ? <Pill tone="success">{t("result.indication.Valid")}</Pill> : value === "Invalid" ? <Pill tone="danger">{t("result.indication.Invalid")}</Pill> : <Pill tone="warning">{t("result.indication.Indeterminate")}</Pill>
  return subIndication && value !== "Valid"
    ? <span className="inline-flex items-center gap-1.5">{pill}<span className="text-muted-foreground font-mono text-xs" title="ETSI EN 319 102-1">{subIndication}</span></span>
    : pill
}

export function SignatureCard({ report }: { report: SignatureReport }) {
  const t = useT()
  return (
    <div className="rounded-lg border">
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        <FileCheck2 className="size-4" />
        <span className="font-medium">{report.fieldName}</span>
        {report.isDocumentTimestamp && <Pill tone="info">{t("result.report.docTimestamp")}</Pill>}
        <span className="text-muted-foreground text-xs">{report.signer}</span>
        <span className="ml-auto"><Indication value={report.indication} subIndication={report.subIndication} /></span>
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

export function CodeTabs({ code }: { code: CodeSnippets }) {
  return (
    <Tabs defaultValue="csharp">
      <TabsList>
        <TabsTrigger value="csharp">C#</TabsTrigger>
        <TabsTrigger value="cli">CLI</TabsTrigger>
      </TabsList>
      <TabsContent value="csharp" className="pt-3"><CodeBlock code={code.cSharp} /></TabsContent>
      <TabsContent value="cli" className="space-y-3 pt-3">
        <CodeBlock code={code.cli} />
        {code.cliNotes.length > 0 && <ul className="text-muted-foreground space-y-1 text-xs">{code.cliNotes.map((n, i) => <li key={i}>• {n}</li>)}</ul>}
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
