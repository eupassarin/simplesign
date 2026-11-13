import { useRef, useState } from "react"
import { Check, ChevronDown, Landmark, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { useT, type MessageKey } from "@/i18n"
import { cn } from "@/lib/utils"
import { asText, getPath, setPath, type Options } from "./schema"

// A trust framework (one at a time) is a set of field values: trust choices, the policies and, for ICP-Brasil, the
// signature levels. The options stay the single source of truth: the framework on is the one whose trust choice is
// there, and everything it changes shows in its own field.

export type Framework = "Peru" | "IcpBrasil" | "GovBr"

/** Where the framework applies: Sign (signing and the validation after it) or Validate. */
export type FrameworkPage = "sign" | "validate"

interface FrameworkDefinition {
  /** The signing policy preset; absent where the framework cannot sign (Gov.br). */
  signing?: string
  validation: string
  flag: string
}

export const frameworks: Record<Framework, FrameworkDefinition> = {
  Peru: { signing: "preset:signing:iofe", validation: "preset:validation:iofe", flag: "🇵🇪" },
  IcpBrasil: { signing: "preset:signing:icp-brasil", validation: "preset:validation:icp-brasil", flag: "🇧🇷" },
  GovBr: { validation: "preset:validation:govbr", flag: "🇧🇷" },
}

const all = Object.keys(frameworks) as Framework[]

/** The frameworks a page offers: Gov.br only validates. */
export function frameworksOf(page: FrameworkPage): Framework[] {
  return page === "sign" ? all.filter((f) => frameworks[f].signing) : all
}

function list(options: Options, path: string): string[] {
  const value = getPath(options, path)
  return Array.isArray(value) ? (value as string[]) : []
}

/**
 * The trust choices that belong to each framework: shown only while it is on. Peru has two lists, one or the other:
 * INDECOPI's real list, and the Sandbox's list in INDECOPI's layout to test with the Sandbox's certificates.
 */
export const frameworkTrustValues: Record<Framework, string[]> = {
  Peru: ["Peru", "SandboxIofeList"],
  IcpBrasil: ["IcpBrasil"],
  GovBr: ["GovBr"],
}

const specificTrustValues = Object.values(frameworkTrustValues).flat()

/** Whether a trust choice is shown: the general ones always, a framework's only while it is on. */
export function isTrustValueShown(value: string, active: Framework | null): boolean {
  return !specificTrustValues.includes(value) || (active !== null && frameworkTrustValues[active].includes(value))
}

/** The framework on: the one whose trust choice the options carry (validation trust, else signing trust). */
export function activeFramework(options: Options): Framework | null {
  const chosen = [...list(options, "validation.trust"), ...list(options, "signingControls.trust")]
  return all.find((f) => frameworkTrustValues[f].some((v) => chosen.includes(v))) ?? null
}

/** The policy preset the active framework puts at <paramref name="path"/>, or null. */
export function frameworkPolicy(framework: Framework | null, path: string): string | null {
  if (!framework) return null
  return (path === "signingPolicyId" ? frameworks[framework].signing : path === "validation.policyId" ? frameworks[framework].validation : null) ?? null
}

/** The ICP-Brasil policy closest to a baseline level, and back. */
const icpOfLevel: Record<string, string> = { BB: "AdRb", BT: "AdRt", BLT: "AdRc", BLTA: "AdRa" }
const levelOfIcp: Record<string, string> = { AdRb: "BB", AdRt: "BT", AdRv: "BLT", AdRc: "BLTA", AdRa: "BLTA" }

/** What turning a framework on or off writes, remembered so turning it off puts the previous policies back. */
export interface FrameworkMemory {
  signingPolicyId?: string | null
  validationPolicyId?: string | null
}

/**
 * The options with <paramref name="next"/> on (null: none): the other frameworks' trust choices removed, this one's
 * added, the policies set to its presets (or back to <paramref name="memory"/> when one is turned off and its preset is
 * still there), and on Sign the ICP-Brasil levels in place of the baseline ones.
 */
export function applyFramework(options: Options, next: Framework | null, page: FrameworkPage, memory: FrameworkMemory): Options {
  const previous = activeFramework(options)
  let o = options
  const swap = (path: string) => {
    if (getPath(o, path) === undefined) return
    const kept = list(o, path).filter((v) => !specificTrustValues.includes(v))
    o = setPath(o, path, next && (path === "validation.trust" || frameworks[next].signing) ? [...kept, next] : kept)
  }
  const policy = (path: string, remembered: string | null | undefined) => {
    const target = frameworkPolicy(next, path)
    if (target) o = setPath(o, path, target)
    else if (previous && asText(getPath(o, path)) === frameworkPolicy(previous, path)) o = setPath(o, path, remembered ?? null)
  }

  swap("validation.trust")
  policy("validation.policyId", memory.validationPolicyId)
  if (page === "sign") {
    swap("signingControls.trust")
    policy("signingPolicyId", memory.signingPolicyId)
    if (next === "IcpBrasil" && asText(o.kind) !== "IcpBrasil") {
      o = setPath(setPath(o, "kind", "IcpBrasil"), "icpPolicy", icpOfLevel[asText(o.level)] ?? "AdRb")
    } else if (next !== "IcpBrasil" && asText(o.kind) === "IcpBrasil") {
      o = setPath(setPath(o, "kind", "Baseline"), "level", levelOfIcp[asText(o.icpPolicy)] ?? "BB")
    }
  }

  return o
}

/** The policies before a framework was turned on, to put back when it is turned off. */
export function rememberPolicies(options: Options): FrameworkMemory {
  return {
    signingPolicyId: getPath(options, "signingPolicyId") as string | null | undefined,
    validationPolicyId: getPath(options, "validation.policyId") as string | null | undefined,
  }
}

const titleKey: Record<Framework, MessageKey> = { Peru: "wb.framework.peru", IcpBrasil: "wb.framework.icpBrasil", GovBr: "wb.framework.govBr" }

/** What a framework changes on a page, one line per field, for the hover card, the strip and the toast. */
function effects(framework: Framework, page: FrameworkPage, t: ReturnType<typeof useT>): string[] {
  const lines: string[] = []
  if (page === "sign" && frameworks[framework].signing) lines.push(t("wb.framework.effect.signingPolicy", { policy: frameworks[framework].signing!.split(":")[2] }))
  lines.push(t("wb.framework.effect.validationPolicy", { policy: frameworks[framework].validation.split(":")[2] }))
  lines.push(t(framework === "Peru" ? "wb.framework.effect.trustPeru" : framework === "IcpBrasil" ? "wb.framework.effect.trustIcp" : "wb.framework.effect.trustGovBr"))
  if (page === "sign" && framework === "IcpBrasil") lines.push(t("wb.framework.effect.levels"))
  lines.push(t("wb.framework.effect.realCertificates"))
  return lines
}

/**
 * The trust frameworks of a page as one menu button (as the Playbook menu): "None" or one framework; each item says what
 * it changes. The button shows the framework on; turning one on or off says it in a toast.
 */
export function FrameworkMenu({ page, options, update }: {
  page: FrameworkPage
  options: Options
  update: (change: (current: Options) => Options) => void
}) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const memory = useRef<FrameworkMemory>({})
  const active = activeFramework(options)
  const choose = (next: Framework | null) => {
    setOpen(false)
    if (next === active) return
    if (!active) memory.current = rememberPolicies(options)
    update((current) => applyFramework(current, next, page, memory.current))
    if (next) toast.success(t("wb.framework.on", { name: t(titleKey[next]) }), { description: effects(next, page, t).join(" · ") })
    else if (active) toast(t("wb.framework.off", { name: t(titleKey[active]) }), { description: t("wb.framework.offHint") })
  }
  const item = "hover:bg-accent hover:text-accent-foreground flex w-full items-start gap-2 rounded-sm px-2 py-1.5 text-left"

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={t("wb.framework.title")}
          className={cn(active && "border-primary/40 bg-primary/10 text-primary hover:bg-primary/15 border")}>
          {active ? <span aria-hidden>{frameworks[active].flag}</span> : <Landmark />}
          {active ? t(titleKey[active]) : t("wb.framework.title")}
          <ChevronDown className="opacity-60" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-1">
        <button type="button" className={item} onClick={() => choose(null)}>
          <Check className={cn("mt-0.5 size-4 shrink-0", active ? "opacity-0" : "opacity-100")} />
          <span className="min-w-0">
            <span className="block text-sm font-medium">{t("wb.framework.none")}</span>
            <span className="text-muted-foreground block text-xs">{t("wb.framework.noneHint")}</span>
          </span>
        </button>
        <div className="bg-border -mx-1 my-1 h-px" />
        {frameworksOf(page).map((f) => (
          <button key={f} type="button" className={cn(item, active === f && "bg-accent/50")} onClick={() => choose(f)}>
            <Check className={cn("mt-0.5 size-4 shrink-0", active === f ? "opacity-100" : "opacity-0")} />
            <span className="min-w-0">
              <span className="block text-sm font-medium"><span aria-hidden>{frameworks[f].flag}</span> {t(titleKey[f])}</span>
              <span className="text-muted-foreground mt-0.5 block space-y-0.5 text-xs">
                {effects(f, page, t).map((line) => <span key={line} className="block">{line}</span>)}
              </span>
            </span>
          </button>
        ))}
        <p className="text-muted-foreground border-t px-2 pt-1.5 pb-1 text-[11px]">{t("wb.framework.dssNote")}</p>
      </PopoverContent>
    </Popover>
  )
}

/** The strip under the top bar while a framework is on: what it changed, in one line. */
export function FrameworkStrip({ page, options }: { page: FrameworkPage; options: Options }) {
  const t = useT()
  const active = activeFramework(options)
  if (!active) return null
  return (
    <div className="border-primary/30 bg-primary/5 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border px-3 py-1.5 text-xs">
      <ShieldCheck className="text-primary size-3.5 shrink-0" />
      <span className="font-medium">{t("wb.framework.on", { name: `${frameworks[active].flag} ${t(titleKey[active])}` })}</span>
      <span className="text-muted-foreground">{effects(active, page, t).join(" · ")}</span>
    </div>
  )
}

/**
 * The marker of a field a framework sets (a policy, a trust choice): the framework's name when the field holds its
 * value, a warning when the framework is on and the field was changed by hand.
 */
export function FrameworkMarker({ options, path, value }: { options: Options; path: string; value?: string }) {
  const t = useT()
  const active = activeFramework(options)
  if (!active) return null
  const expected = value ?? frameworkPolicy(active, path)
  if (expected === null) return null
  const matches = value !== undefined ? value === active : asText(getPath(options, path)) === expected
  return (
    <span title={t(matches ? "wb.framework.markerHint" : "wb.framework.markerDiffers", { name: t(titleKey[active]) })}
      className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium",
        matches ? "border-primary/40 bg-primary/10 text-primary" : "border-warning/50 bg-warning/10")}>
      <span aria-hidden>{frameworks[active].flag}</span>{matches ? t(titleKey[active]) : t("wb.framework.notFrameworks", { name: t(titleKey[active]) })}
    </span>
  )
}
