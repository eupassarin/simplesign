import { Layers3, Split, Zap } from "lucide-react"
import { Input } from "@/components/ui/input"
import { useT } from "@/i18n"
import { ChoiceCard, Field, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

export function ModeStep() {
  const { options, update, state } = useSigning()
  const t = useT()
  return (
    <div className="space-y-8">
      <Section title={t("mode.title")} description={t("mode.hint")}>
        <div className="grid gap-3 md:grid-cols-3">
          <ChoiceCard selected={options.mode === "Sign"} onSelect={() => update({ mode: "Sign" })} title={t("mode.Sign.title")} infoId="mode.Sign" icon={<Zap className="size-4" />}
            description={t("mode.Sign.hint")} state={state("mode.Sign")} />
          <ChoiceCard selected={options.mode === "Deferred"} onSelect={() => update({ mode: "Deferred" })} title={t("mode.Deferred.title")} infoId="mode.Deferred" icon={<Split className="size-4" />}
            description={t("mode.Deferred.hint")} state={state("mode.Deferred")} />
          <ChoiceCard selected={options.mode === "Batch"} onSelect={() => update({ mode: "Batch" })} title={t("mode.Batch.title")} infoId="mode.Batch" icon={<Layers3 className="size-4" />}
            description={t("mode.Batch.hint")} state={state("mode.Batch")} />
        </div>
      </Section>

      {options.mode === "Deferred" && (
        <ol className="text-muted-foreground list-decimal space-y-1 rounded-lg border p-4 pl-8 text-sm">
          <li><b className="text-foreground">{t("mode.phases.prepare")}</b> {t("mode.phases.prepareHint")}</li>
          <li><b className="text-foreground">{t("mode.phases.sign")}</b> {t("mode.phases.signHint")}</li>
          <li><b className="text-foreground">{t("mode.phases.complete")}</b> {t("mode.phases.completeHint")}</li>
        </ol>
      )}

      {state("batch").visible && (
        <div className="grid max-w-md grid-cols-2 gap-4">
          <Field label={t("mode.copies")} description={t("mode.copiesHint")}><Input type="number" min={1} max={50} value={options.batchCopies} onChange={(e) => update({ batchCopies: Number(e.target.value) })} /></Field>
          <Field label={t("mode.concurrency")} description={t("mode.concurrencyHint")}><Input type="number" min={1} max={16} value={options.maxConcurrency} onChange={(e) => update({ maxConcurrency: Number(e.target.value) })} /></Field>
        </div>
      )}

      <ToggleRow checked={options.validate} onChange={(validate) => update({ validate })} label={t("mode.validate")}
        description={t(options.environment === "Sandbox" ? "mode.validateSandbox" : "mode.validateReal")} />
    </div>
  )
}
