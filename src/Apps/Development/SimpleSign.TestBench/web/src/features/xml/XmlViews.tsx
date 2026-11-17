import { useI18n } from "@/i18n"
import type { XmlValidationView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { Indication } from "../shared/results"
import { Pill, Section } from "../shared/ui"

export function SignatureList({ view }: { view: XmlValidationView }) {
  const { t } = useI18n()
  return (
    <div className="space-y-3">
      {view.errors.length > 0 && <ul className="text-destructive space-y-1 text-xs">{view.errors.map((e) => <li key={e}>✕ {e}</li>)}</ul>}
      {view.signatures.map((s) => (
        <div key={s.index} className="rounded-lg border">
          <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
            <span className="text-sm font-medium">{t("cades.result.signer", { n: s.index + 1 })}</span>
            <span className="text-muted-foreground truncate text-sm">{s.signer ?? "—"}</span>
            {s.level && <Pill>{s.level}</Pill>}
            {s.reference && <span className="text-muted-foreground font-mono text-xs">{s.reference}</span>}
            <span className="ml-auto"><Indication value={s.indication} subIndication={s.subIndication} /></span>
          </div>
          <div className="divide-y px-4">
            {s.checks.map((c) => (
              <div key={c.id} className="flex items-start gap-3 py-2 text-sm">
                <span className={cn("mt-0.5 size-2 shrink-0 rounded-full", c.status === "pass" ? "bg-success" : c.status === "fail" ? "bg-destructive" : c.status === "warn" ? "bg-warning" : "bg-muted-foreground/40")} />
                <span className="min-w-0 flex-1">{c.name}{c.detail && <span className="text-muted-foreground block text-xs break-words">{c.detail}</span>}</span>
                <span className="text-muted-foreground text-xs">{c.status}</span>
              </div>
            ))}
          </div>
          {(s.errors.length > 0 || s.warnings.length > 0) && (
            <ul className="space-y-1 border-t px-4 py-2 text-xs">
              {s.errors.map((e) => <li key={e} className="text-destructive">✕ {e}</li>)}
              {s.warnings.map((w) => <li key={w} className="text-muted-foreground">! {w}</li>)}
            </ul>
          )}
        </div>
      ))}
    </div>
  )
}

export function XmlViews({ view }: { view: XmlValidationView }) {
  const { t } = useI18n()
  return (
    <>
      {view.signatureXml && (
        <Section title={t("xml.result.signature")} description={t("xml.result.signatureHint")}>
          <pre className="bg-muted max-h-96 overflow-auto rounded-lg p-4 font-mono text-xs leading-relaxed">{view.signatureXml}</pre>
        </Section>
      )}
      <Section title={t("xml.result.document")} description={t("xml.result.documentHint")}>
        <pre className="bg-muted max-h-72 overflow-auto rounded-lg p-4 font-mono text-xs leading-relaxed">{view.documentPreview}</pre>
      </Section>
    </>
  )
}
