import { useEffect, useState } from "react"
import { ArrowUpFromLine, Info, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { TsaPicker } from "../shared/TsaPicker"
import { Pill } from "../shared/ui"
import { Block, SignedFilePicker, useOpenBlocks } from "../validate/parts"
import { OptionField, OptionScope } from "../workbench/fields"
import { ProfileMenu, ProfileStrip } from "../workbench/profile"
import { ResultPanel } from "../workbench/ResultPanel"
import type { ValidationSampleView } from "../workbench/schema"
import { useWorkbench, type AugmentSettings } from "../workbench/state"
import { HistoryDrawer } from "../workbench/WorkbenchPage"

const levels: AugmentSettings["level"][] = ["BT", "BLT", "BLTA"]
const levelTitle: Record<AugmentSettings["level"], string> = { BT: "B-T", BLT: "B-LT", BLTA: "B-LTA" }
const openByDefault: Record<string, boolean> = { file: true, "samples.pades": true, level: true, trust: false }

/**
 * The Augment task: a signed file (made on the Sign tab, a sample, or uploaded from any other product) raised to
 * B-T, B-LT or B-LTA without signing again, or a B-LTA whose archive time-stamp is renewed, through the format's
 * augmenter (PadesAugmenter, CadesAugmenter, XadesAugmenter). The result is validated with the Validate tab's trust,
 * and can be augmented again, so a chain B-B → B-T → B-LT → B-LTA → renewal is a few clicks.
 */
export function AugmentPage() {
  const { schema, env, state, augmentTarget, setAugmentTarget, augmentSettings, setAugmentSettings, augment, running, run, engine,
    validateOptions, setValidateOption, updateValidate } = useWorkbench()
  const t = useT()
  const [samples, setSamples] = useState<ValidationSampleView[]>([])
  useEffect(() => {
    api.workbench.samples().then(setSamples).catch(() => setSamples([]))
  }, [schema])
  const { open, toggle } = useOpenBlocks("aug.sections", openByDefault)
  const set = <K extends keyof AugmentSettings>(key: K, value: AugmentSettings[K]) => setAugmentSettings((current) => ({ ...current, [key]: value }))
  const trust = schema.options.find((o) => o.id === "common.validation.trust")
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 border-b px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className="text-sm">
            {augmentTarget
              ? <><span className="font-medium">{augmentTarget.name}</span>{augmentTarget.dataName && <span className="text-muted-foreground"> + {augmentTarget.dataName}</span>}</>
              : <span className="text-muted-foreground">{t("aug.noFile")}</span>}
          </span>
          {run?.success && run.initialLevel && <Pill>{run.initialLevel} → {run.achievedLevel}</Pill>}
          <div className="ml-auto flex items-center gap-2">
            <ProfileMenu page="validate" options={validateOptions} update={updateValidate} />
            <HistoryDrawer />
            <Button className="min-w-36" disabled={!augmentTarget || running} onClick={() => void augment()}>
              {running ? <Loader2 className="animate-spin" /> : <ArrowUpFromLine />} {t("aug.run")}
            </Button>
          </div>
        </div>
        <ProfileStrip page="validate" options={validateOptions} />
      </div>
      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(400px,5fr)_7fr]">
        <div className="min-h-0 space-y-3 overflow-y-auto border-r p-4">
          <Block id="file" title={t("aug.file")} summary={t("aug.fileHint")} open={open} toggle={toggle}>
            <SignedFilePicker target={augmentTarget} onChoose={setAugmentTarget} samples={samples} open={open} toggle={toggle} />
          </Block>

          <Block id="level" title={t("aug.level")} summary={t("aug.levelHint")} open={open} toggle={toggle}>
            <div className="space-y-4 py-3">
              <div className="space-y-2">
                <p className="text-sm font-medium">{t("aug.levelLabel")}</p>
                <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label={t("aug.levelLabel")}>
                  {levels.map((level) => (
                    <button key={level} type="button" role="radio" aria-checked={augmentSettings.level === level} onClick={() => set("level", level)}
                      className={cn("rounded-lg border p-2.5 text-left transition-colors", augmentSettings.level === level ? "border-primary bg-primary/5" : "hover:bg-accent/40")}>
                      <span className="block font-mono text-sm font-semibold">{levelTitle[level]}</span>
                      <span className="text-muted-foreground block text-xs leading-snug">{t(`aug.level${level}` as MessageKey)}</span>
                    </button>
                  ))}
                </div>
              </div>
              <Label className="flex items-start gap-2 font-normal">
                <Switch className="mt-0.5" checked={augmentSettings.renew} onCheckedChange={(v) => set("renew", v)} />
                <span>
                  <span className="block text-sm font-medium">{t("aug.renew")} <code className="text-muted-foreground font-mono text-[11px]">RenewArchive()</code></span>
                  <span className="text-muted-foreground block text-xs">{t("aug.renewHint")}</span>
                </span>
              </Label>
              <div className="space-y-2">
                <p className="text-sm font-medium">{t("aug.tsa")}</p>
                <TsaPicker value={augmentSettings.timestamp} onChange={(v) => set("timestamp", v)} state={state} env={env} />
              </div>
            </div>
          </Block>

          <Block id="trust" title={t("aug.trust")} summary={t("aug.trustHint")} count={trust ? 1 : undefined} open={open} toggle={toggle}>
            <div className="space-y-2 py-3">
              <p className="text-muted-foreground text-xs">{t("aug.trustNote")}</p>
              {trust && (
                <OptionScope.Provider value={{ options: validateOptions, set: setValidateOption }}>
                  <OptionField option={trust} />
                </OptionScope.Provider>
              )}
            </div>
          </Block>

          {engine === "cli" && (
            <p className="text-muted-foreground flex items-start gap-2 px-1 text-xs"><Info className="mt-0.5 size-3.5 shrink-0" /> {t("aug.cliNote")}</p>
          )}
        </div>
        <div className="min-h-0 overflow-y-auto p-4">
          <ResultPanel />
        </div>
      </div>
    </div>
  )
}
