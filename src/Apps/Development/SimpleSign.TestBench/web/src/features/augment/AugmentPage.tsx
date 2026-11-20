import { useEffect, useRef, useState } from "react"
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
import { activeProfile, ProfileMenu, ProfileStrip } from "../workbench/profile"
import { ResultPanel } from "../workbench/ResultPanel"
import type { AugmentFacts, ValidationSampleView } from "../workbench/schema"
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
 *
 * With the ICP-Brasil profile on, the levels stay B-T, B-LT and B-LTA: the ICP-Brasil policy (AD-RB…AD-RA) is a signed
 * attribute chosen when signing, which augmenting keeps. The tab shows the policy the file declares, what the
 * augmenter can add for it, and picks the level that brings it.
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

  // The ICP-Brasil policy the file declares: read when the file is chosen, shown while the profile is on.
  const [facts, setFacts] = useState<AugmentFacts | null>(null)
  const picked = useRef(false)
  const fileId = augmentTarget?.fileId
  useEffect(() => {
    setFacts(null)
    picked.current = false
    if (!fileId) return
    let live = true
    api.workbench.describeAugment(fileId).then((f) => { if (live) setFacts(f) }).catch(() => { if (live) setFacts(null) })
    return () => { live = false }
  }, [fileId])
  const icp = activeProfile(validateOptions)?.profile === "IcpBrasil"
  const policy = icp ? facts?.icpPolicy ?? null : null
  const recommended = policy?.recommended ?? null
  useEffect(() => {
    // The level that brings what the declared policy needs, unless one was chosen for this file.
    if (recommended && !picked.current) setAugmentSettings((current) => ({ ...current, level: recommended }))
  }, [recommended, setAugmentSettings])
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 border-b px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className="text-sm">
            {augmentTarget
              ? <><span className="font-medium">{augmentTarget.name}</span>{augmentTarget.dataName && <span className="text-muted-foreground"> + {augmentTarget.dataName}</span>}</>
              : <span className="text-muted-foreground">{t("aug.noFile")}</span>}
          </span>
          {policy && <Pill tone="info">{t("aug.icp.declares", { policy: policy.name })} · <span className="font-mono">{policy.oid}</span></Pill>}
          {run?.success && run.initialLevel && <Pill>{run.initialLevel} → {run.achievedLevel}</Pill>}
          <div className="ml-auto flex items-center gap-2">
            <ProfileMenu page="validate" options={validateOptions} update={updateValidate} />
            <HistoryDrawer />
            <Button className="min-w-36" disabled={!augmentTarget || running} onClick={() => void augment()}>
              {running ? <Loader2 className="animate-spin" /> : <ArrowUpFromLine />} {t("aug.run")}
            </Button>
          </div>
        </div>
        <ProfileStrip page="validate" options={validateOptions} notes={icp ? [t("aug.icp.strip")] : []} />
      </div>
      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(400px,5fr)_7fr]">
        <div className="min-h-0 space-y-3 overflow-y-auto border-r p-4">
          <Block id="file" title={t("aug.file")} summary={t("aug.fileHint")} open={open} toggle={toggle}>
            <SignedFilePicker target={augmentTarget} onChoose={setAugmentTarget} samples={samples} open={open} toggle={toggle} />
          </Block>

          <Block id="level" title={t("aug.level")} summary={t("aug.levelHint")} open={open} toggle={toggle}>
            <div className="space-y-4 py-3">
              {policy && (
                <div className="border-primary/30 bg-primary/5 space-y-1 rounded-md border px-3 py-2 text-xs">
                  <p>{t("aug.icp.keeps", { policy: policy.name, oid: policy.oid })}</p>
                  {policy.notes.length > 0 && (
                    <ul className="text-muted-foreground list-disc space-y-0.5 pl-4">
                      {policy.notes.map((note) => <li key={note}>{t(`aug.icp.notes.${note}` as MessageKey, { policy: policy.name })}</li>)}
                    </ul>
                  )}
                </div>
              )}
              <div className="space-y-2">
                <p className="text-sm font-medium">{t("aug.levelLabel")}</p>
                <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label={t("aug.levelLabel")}>
                  {levels.map((level) => (
                    <button key={level} type="button" role="radio" aria-checked={augmentSettings.level === level} onClick={() => { picked.current = true; set("level", level) }}
                      className={cn("rounded-lg border p-2.5 text-left transition-colors", augmentSettings.level === level ? "border-primary bg-primary/5" : "hover:bg-accent/40")}>
                      <span className="block font-mono text-sm font-semibold">{levelTitle[level]}</span>
                      <span className="text-muted-foreground block text-xs leading-snug">{t(`aug.level${level}` as MessageKey)}</span>
                      {policy && recommended === level && (
                        <span className="border-primary/40 bg-primary/10 text-primary mt-1.5 inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium">
                          {t("aug.icp.recommended", { policy: policy.name })}
                        </span>
                      )}
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
