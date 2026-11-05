import { useMemo, useState, type ComponentType } from "react"
import { ArrowLeft, ArrowRight, Check, CircleAlert, Loader2, PenTool, RotateCcw } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { api } from "@/lib/api"
import type { SigningResult } from "@/lib/types"
import { cn } from "@/lib/utils"
import { useSigning } from "./state"
import { CryptoStep } from "./steps/CryptoStep"
import { DetailsStep } from "./steps/DetailsStep"
import { DocumentStep } from "./steps/DocumentStep"
import { FieldStep } from "./steps/FieldStep"
import { ModeStep } from "./steps/ModeStep"
import { ResultView, SigningSpinner } from "./steps/ResultStep"
import { SignerStep } from "./steps/SignerStep"
import { TypeStep } from "./steps/TypeStep"
import { IssueList, KeyValue } from "./ui"

interface Step {
  id: string
  title: string
  subtitle: string
  component: ComponentType
}

const steps: Step[] = [
  { id: "document", title: "Document", subtitle: "The PDF to sign", component: DocumentStep },
  { id: "signer", title: "Signer", subtitle: "A1, A3, store or cloud", component: SignerStep },
  { id: "type", title: "Signature type", subtitle: "Baseline, ICP-Brasil, policy", component: TypeStep },
  { id: "crypto", title: "Cryptography", subtitle: "Digest, scheme, sub-filter", component: CryptoStep },
  { id: "field", title: "Field & appearance", subtitle: "Where and how it shows", component: FieldStep },
  { id: "details", title: "Details", subtitle: "Reason, signer, certification", component: DetailsStep },
  { id: "mode", title: "Mode", subtitle: "Now, deferred or batch", component: ModeStep },
]

export function SigningPage() {
  const { options, report, document, credential, evaluating, reset } = useSigning()
  const [current, setCurrent] = useState(0)
  const [result, setResult] = useState<SigningResult | null>(null)
  const [signing, setSigning] = useState(false)
  const showingResult = current === steps.length
  const issues = report?.issues ?? []
  const errorsByStep = useMemo(() => {
    const map = new Map<string, number>()
    for (const i of issues) if (i.severity === "Error") map.set(i.step, (map.get(i.step) ?? 0) + 1)
    return map
  }, [issues])

  async function sign() {
    setCurrent(steps.length)
    setSigning(true)
    setResult(null)
    try {
      const r = await api.sign(options)
      setResult(r)
      if (!r.success) toast.error("Signing failed", { description: r.error ?? undefined })
    } catch (e) {
      toast.error("Signing failed", { description: (e as Error).message })
    } finally {
      setSigning(false)
    }
  }

  const step = steps[current]
  const StepComponent = step?.component
  const stepIssues = step ? issues.filter((i) => i.step === step.id) : []
  return (
    <div className="grid min-h-0 flex-1 lg:grid-cols-[230px_minmax(0,1fr)_300px]">
      <nav className="border-r p-3 max-lg:hidden">
        <ol className="space-y-0.5">
          {steps.map((s, i) => {
            const errors = errorsByStep.get(s.id) ?? 0
            return (
              <li key={s.id}>
                <button onClick={() => setCurrent(i)}
                  className={cn("flex w-full items-start gap-3 rounded-md px-2.5 py-2 text-left transition-colors", i === current ? "bg-accent" : "hover:bg-accent/50")}>
                  <span className={cn("mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[11px] font-medium",
                    i === current && "border-primary bg-primary text-primary-foreground", errors > 0 && i !== current && "border-destructive text-destructive")}>
                    {errors > 0 ? "!" : i < current ? <Check className="size-3" /> : i + 1}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">{s.title}</span>
                    <span className="text-muted-foreground block truncate text-xs">{s.subtitle}</span>
                  </span>
                </button>
              </li>
            )
          })}
          <li>
            <button onClick={() => result && setCurrent(steps.length)} disabled={!result}
              className={cn("flex w-full items-start gap-3 rounded-md px-2.5 py-2 text-left", showingResult ? "bg-accent" : "hover:bg-accent/50", !result && "opacity-50")}>
              <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[11px]">✓</span>
              <span><span className="block text-sm font-medium">Result</span><span className="text-muted-foreground block text-xs">Report and code</span></span>
            </button>
          </li>
        </ol>
        <Separator className="my-3" />
        <Button variant="ghost" size="sm" className="w-full justify-start" onClick={() => { reset(); setCurrent(0); setResult(null) }}>
          <RotateCcw /> Start over
        </Button>
      </nav>

      <div className="min-h-0 min-w-0 overflow-y-auto">
        <div className="mx-auto max-w-5xl space-y-6 p-6 lg:p-8">
          <header className="space-y-1">
            <p className="text-muted-foreground text-xs font-medium tracking-wide uppercase">{showingResult ? "Result" : `Step ${current + 1} of ${steps.length}`}</p>
            <h2 className="text-2xl font-semibold tracking-tight">{showingResult ? "Signed PDF" : step.title}</h2>
          </header>
          {!showingResult && stepIssues.length > 0 && <IssueList issues={stepIssues} />}
          {showingResult ? signing ? <SigningSpinner /> : result && <ResultView result={result} /> : StepComponent && <StepComponent />}
          {!showingResult && (
            <div className="flex items-center justify-between border-t pt-6">
              <Button variant="outline" onClick={() => setCurrent((c) => Math.max(0, c - 1))} disabled={current === 0}><ArrowLeft /> Back</Button>
              {current < steps.length - 1 ? (
                <Button onClick={() => setCurrent((c) => c + 1)}>Next <ArrowRight /></Button>
              ) : (
                <Button onClick={sign} disabled={!report?.canSign || signing}>{signing ? <Loader2 className="animate-spin" /> : <PenTool />} Sign</Button>
              )}
            </div>
          )}
        </div>
      </div>

      <aside className="bg-muted/20 border-l max-lg:hidden">
        <div className="h-full overflow-y-auto">
          <div className="space-y-5 p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">Your signature</h3>
              {evaluating && <Loader2 className="text-muted-foreground size-3.5 animate-spin" />}
            </div>
            <div className="divide-y rounded-lg border bg-background px-3">
              <KeyValue label="Document">{document?.fileName ?? "—"}</KeyValue>
              <KeyValue label="Signer">{credential?.holder ?? "—"}</KeyValue>
              <KeyValue label="Level">{report?.effectiveLevel ?? "—"}</KeyValue>
              <KeyValue label="Digest">{report?.effective.hash.replace("Sha3_", "SHA3-").replace("Sha", "SHA-")}</KeyValue>
              {credential?.keyAlgorithm === "RSA" && <KeyValue label="Scheme">{report?.effective.padding === "Pss" ? "RSASSA-PSS" : "PKCS#1 v1.5"}</KeyValue>}
              <KeyValue label="Sub-filter" mono>{report?.effective.subFilter.replace("EtsiCadesDetached", "ETSI.CAdES.detached").replace("AdbePkcs7Detached", "adbe.pkcs7.detached").replace("PbadPades", "PBAD.PAdES")}</KeyValue>
              <KeyValue label="Field">{report?.effective.fieldMode === "Existing" ? `existing “${report.effective.existingFieldName}”` : options.fieldName}</KeyValue>
              <KeyValue label="Stamp">{options.appearance.visible ? "visible" : "invisible"}</KeyValue>
              <KeyValue label="Mode">{options.mode}</KeyValue>
            </div>
            {issues.length === 0 ? (
              <p className="text-success flex items-center gap-1.5 text-xs"><Check className="size-3.5" /> Every option is compatible.</p>
            ) : (
              <div className="space-y-2">
                <p className="flex items-center gap-1.5 text-xs font-medium"><CircleAlert className="size-3.5" /> Notes on this combination</p>
                <IssueList issues={issues} />
              </div>
            )}
            <Button className="w-full" onClick={sign} disabled={!report?.canSign || signing}>
              {signing ? <Loader2 className="animate-spin" /> : <PenTool />} Sign now
            </Button>
          </div>
        </div>
      </aside>
    </div>
  )
}
