import { useRef, useState } from "react"
import { Check, ChevronDown, Landmark, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { useT, type MessageKey } from "@/i18n"
import { cn } from "@/lib/utils"
import { asText, getPath, setPath, type Options } from "./schema"

// A trust profile (SimpleSign's TrustProfile: IofeProfile, IcpBrasilProfile, GovBrProfile, the Sandbox's) is one option of
// its own, `profile` (with `profileSource` for IOFE and `trustProfiles` for the others' trust), on the signing controls and
// on the validation. Only one profile sets the policies: the menu writes its presets in the policy fields, where they show.

export type Profile = "Sandbox" | "Iofe" | "IcpBrasil" | "GovBr"
export type ProfileSource = "Indecopi" | "Sandbox"

/** The profile on: which one, and for IOFE which list it reads. */
export interface ProfileChoice {
  profile: Profile
  source: ProfileSource
}

/** Where the profile applies: Sign (signing and the validation after it) or Validate. */
export type ProfilePage = "sign" | "validate"

interface ProfileDefinition {
  /** The signing policy preset; absent where the profile sets SimpleSign's default (Sandbox) or cannot sign (Gov.br). */
  signing?: string
  validation?: string
  /** Whether signatures are made under it (Gov.br's are made on Gov.br's service). */
  signs: boolean
  flag: string
  title: MessageKey
}

export const profiles: Record<Profile, ProfileDefinition> = {
  Sandbox: { signs: true, flag: "🧪", title: "wb.profile.sandbox" },
  Iofe: { signing: "preset:signing:iofe", validation: "preset:validation:iofe", signs: true, flag: "🇵🇪", title: "wb.profile.peru" },
  IcpBrasil: { signing: "preset:signing:icp-brasil", validation: "preset:validation:icp-brasil", signs: true, flag: "🇧🇷", title: "wb.profile.icpBrasil" },
  GovBr: { validation: "preset:validation:govbr", signs: false, flag: "🇧🇷", title: "wb.profile.govBr" },
}

const all = Object.keys(profiles) as Profile[]

/** The menu's entries: Peru twice (INDECOPI's real list, the Sandbox's list), Gov.br on Validate only. */
function entries(page: ProfilePage): ProfileChoice[] {
  return all
    .filter((p) => page === "validate" || profiles[p].signs)
    .flatMap((p): ProfileChoice[] => (p === "Iofe" ? [{ profile: p, source: "Indecopi" }, { profile: p, source: "Sandbox" }] : [{ profile: p, source: "Indecopi" }]))
}

/** The fields the profile is written to on a page: the signing controls (Sign) and the validation. */
function holders(options: Options, page: ProfilePage): string[] {
  return (page === "sign" ? ["signingControls", "validation"] : ["validation"]).filter((p) => getPath(options, p) !== undefined)
}

/** The profile on: the validation's, else the signing controls'; null for none. */
export function activeProfile(options: Options): ProfileChoice | null {
  for (const holder of ["validation", "signingControls"]) {
    const profile = asText(getPath(options, `${holder}.profile`))
    if (profile && profile !== "None" && profile in profiles) {
      return { profile: profile as Profile, source: asText(getPath(options, `${holder}.profileSource`)) === "Sandbox" ? "Sandbox" : "Indecopi" }
    }
  }
  return null
}

/** The profiles whose trust is added. */
export function extraProfiles(options: Options): Profile[] {
  const value = getPath(options, "validation.trustProfiles") ?? getPath(options, "signingControls.trustProfiles")
  return Array.isArray(value) ? (value as Profile[]) : []
}

/** The name of a profile on: "Peru (IOFE) · Sandbox's list". */
export function profileTitle(choice: ProfileChoice, t: ReturnType<typeof useT>): string {
  if (choice.profile !== "Iofe") return t(profiles[choice.profile].title)
  return `${t("wb.profile.peru")} · ${t(choice.source === "Sandbox" ? "wb.profile.listSandbox" : "wb.profile.listIndecopi")}`
}

/** The policy preset the profile puts at <paramref name="path"/>, or null (SimpleSign's default). */
export function profilePolicy(choice: ProfileChoice | null, path: string): string | null {
  if (!choice) return null
  const definition = profiles[choice.profile]
  return (path === "signingPolicyId" ? definition.signing : path === "validation.policyId" ? definition.validation : null) ?? null
}

/** The ICP-Brasil policy closest to a baseline level, and back. */
const icpOfLevel: Record<string, string> = { BB: "AdRb", BT: "AdRt", BLT: "AdRc", BLTA: "AdRa" }
const levelOfIcp: Record<string, string> = { AdRb: "BB", AdRt: "BT", AdRv: "BLT", AdRc: "BLTA", AdRa: "BLTA" }

/** The policies before a profile was turned on, to put back when it is turned off. */
export interface ProfileMemory {
  signingPolicyId?: string | null
  validationPolicyId?: string | null
}

/** The policies of the options, remembered when a profile is turned on. */
export function rememberPolicies(options: Options): ProfileMemory {
  return {
    signingPolicyId: getPath(options, "signingPolicyId") as string | null | undefined,
    validationPolicyId: getPath(options, "validation.policyId") as string | null | undefined,
  }
}

/**
 * The options with <paramref name="next"/> on (null: none): the profile written to its fields, the policies set to its
 * presets (or back to <paramref name="memory"/> when the previous profile's preset is still there), and on Sign the
 * ICP-Brasil levels in place of the baseline ones.
 */
export function applyProfile(options: Options, next: ProfileChoice | null, page: ProfilePage, memory: ProfileMemory): Options {
  const previous = activeProfile(options)
  let o = options
  for (const holder of holders(o, page)) {
    o = setPath(o, `${holder}.profile`, next?.profile ?? "None")
    o = setPath(o, `${holder}.profileSource`, next?.source ?? "Indecopi")
    const extras = getPath(o, `${holder}.trustProfiles`)
    if (next && Array.isArray(extras)) o = setPath(o, `${holder}.trustProfiles`, (extras as string[]).filter((p) => p !== next.profile))
  }

  const policy = (path: string, remembered: string | null | undefined) => {
    if (getPath(o, path) === undefined && path !== "signingPolicyId") return
    const target = profilePolicy(next, path)
    if (target) o = setPath(o, path, target)
    else if (previous && asText(getPath(o, path)) === profilePolicy(previous, path)) o = setPath(o, path, remembered ?? null)
  }
  policy("validation.policyId", memory.validationPolicyId)
  if (page === "sign") {
    policy("signingPolicyId", memory.signingPolicyId)
    const icp = next?.profile === "IcpBrasil"
    if (icp && asText(o.kind) !== "IcpBrasil") {
      o = setPath(setPath(o, "kind", "IcpBrasil"), "icpPolicy", icpOfLevel[asText(o.level)] ?? "AdRb")
    } else if (!icp && asText(o.kind) === "IcpBrasil") {
      o = setPath(setPath(o, "kind", "Baseline"), "level", levelOfIcp[asText(o.icpPolicy)] ?? "BB")
    }
  }
  return o
}

/** The options with <paramref name="extras"/> as the profiles whose trust is added. */
export function applyExtras(options: Options, extras: Profile[], page: ProfilePage): Options {
  let o = options
  for (const holder of holders(o, page)) o = setPath(o, `${holder}.trustProfiles`, extras)
  return o
}

/** What a profile changes on a page, one line per field, for the menu, the strip and the toast. */
function effects(choice: ProfileChoice, page: ProfilePage, t: ReturnType<typeof useT>): string[] {
  const definition = profiles[choice.profile]
  const lines: string[] = []
  const name = (preset: string) => preset.split(":")[2]
  if (page === "sign" && definition.signs) lines.push(t("wb.profile.effect.signingPolicy", { policy: definition.signing ? name(definition.signing) : t("wb.profile.default") }))
  lines.push(t("wb.profile.effect.validationPolicy", { policy: definition.validation ? name(definition.validation) : t("wb.profile.default") }))
  const trust: Record<Profile, MessageKey> = {
    Sandbox: "wb.profile.effect.trustSandbox",
    Iofe: choice.source === "Sandbox" ? "wb.profile.effect.trustPeruSandbox" : "wb.profile.effect.trustPeru",
    IcpBrasil: "wb.profile.effect.trustIcp",
    GovBr: "wb.profile.effect.trustGovBr",
  }
  lines.push(t(trust[choice.profile]))
  if (page === "sign" && choice.profile === "IcpBrasil") lines.push(t("wb.profile.effect.levels"))
  const test = choice.profile === "Sandbox" || choice.source === "Sandbox" && choice.profile === "Iofe"
  lines.push(t(test ? "wb.profile.effect.sandboxCertificates" : "wb.profile.effect.realCertificates"))
  return lines
}

const same = (a: ProfileChoice | null, b: ProfileChoice | null) =>
  a?.profile === b?.profile && (a?.profile !== "Iofe" || a?.source === b?.source)

/**
 * The trust profiles of a page as one menu button (as the Playbook menu): Default or one profile, each saying what it
 * changes, then "Also trust" with the other profiles' trust. The button shows the profile on; turning one on or off
 * says it in a toast.
 */
export function ProfileMenu({ page, options, update }: {
  page: ProfilePage
  options: Options
  update: (change: (current: Options) => Options) => void
}) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const memory = useRef<ProfileMemory>({})
  const active = activeProfile(options)
  const extras = extraProfiles(options)
  const choose = (next: ProfileChoice | null) => {
    setOpen(false)
    if (same(next, active)) return
    if (!active) memory.current = rememberPolicies(options)
    update((current) => applyProfile(current, next, page, memory.current))
    if (next) toast.success(t("wb.profile.on", { name: profileTitle(next, t) }), { description: effects(next, page, t).join(" · ") })
    else if (active) toast(t("wb.profile.off", { name: profileTitle(active, t) }), { description: t("wb.profile.offHint") })
  }
  const toggleExtra = (profile: Profile, on: boolean) =>
    update((current) => applyExtras(current, on ? [...extraProfiles(current).filter((p) => p !== profile), profile] : extraProfiles(current).filter((p) => p !== profile), page))
  const item = "hover:bg-accent hover:text-accent-foreground flex w-full items-start gap-2 rounded-sm px-2 py-1.5 text-left"

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={t("wb.profile.title")}
          className={cn(active && "border-primary/40 bg-primary/10 text-primary hover:bg-primary/15 border")}>
          {active ? <span aria-hidden>{profiles[active.profile].flag}</span> : <Landmark />}
          {active ? profileTitle(active, t) : t("wb.profile.title")}
          {extras.length > 0 && <span className="text-xs opacity-70">+{extras.length}</span>}
          <ChevronDown className="opacity-60" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="max-h-[80vh] w-80 overflow-y-auto p-1">
        <button type="button" className={item} onClick={() => choose(null)}>
          <Check className={cn("mt-0.5 size-4 shrink-0", active ? "opacity-0" : "opacity-100")} />
          <span className="min-w-0">
            <span className="block text-sm font-medium">{t("wb.profile.default")}</span>
            <span className="text-muted-foreground block text-xs">{t("wb.profile.defaultHint")}</span>
          </span>
        </button>
        <div className="bg-border -mx-1 my-1 h-px" />
        {entries(page).map((choice) => (
          <button key={`${choice.profile}-${choice.source}`} type="button" className={cn(item, same(active, choice) && "bg-accent/50")} onClick={() => choose(choice)}>
            <Check className={cn("mt-0.5 size-4 shrink-0", same(active, choice) ? "opacity-100" : "opacity-0")} />
            <span className="min-w-0">
              <span className="block text-sm font-medium"><span aria-hidden>{profiles[choice.profile].flag}</span> {profileTitle(choice, t)}</span>
              <span className="text-muted-foreground mt-0.5 block space-y-0.5 text-xs">
                {effects(choice, page, t).map((line) => <span key={line} className="block">{line}</span>)}
              </span>
            </span>
          </button>
        ))}
        <div className="bg-border -mx-1 my-1 h-px" />
        <div className="px-2 pt-1 pb-1.5">
          <p className="text-sm font-medium">{t("wb.profile.alsoTrust")}</p>
          <p className="text-muted-foreground mb-1.5 text-xs">{t("wb.profile.alsoTrustHint")}</p>
          {all.filter((p) => p !== active?.profile).map((p) => (
            <label key={p} className="flex items-center gap-2 py-0.5 text-sm">
              <Checkbox checked={extras.includes(p)} onCheckedChange={(on) => toggleExtra(p, on === true)} />
              <span aria-hidden>{profiles[p].flag}</span>{t(profiles[p].title)}
            </label>
          ))}
        </div>
        <p className="text-muted-foreground border-t px-2 pt-1.5 pb-1 text-[11px]">{t("wb.profile.dssNote")}</p>
      </PopoverContent>
    </Popover>
  )
}

/** The strip under the top bar while a profile is on (or others' trust is added): what it changed, in one line. */
export function ProfileStrip({ page, options }: { page: ProfilePage; options: Options }) {
  const t = useT()
  const active = activeProfile(options)
  const extras = extraProfiles(options).filter((p) => p !== active?.profile)
  if (!active && extras.length === 0) return null
  return (
    <div className="border-primary/30 bg-primary/5 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border px-3 py-1.5 text-xs">
      <ShieldCheck className="text-primary size-3.5 shrink-0" />
      {active && <span className="font-medium">{t("wb.profile.on", { name: `${profiles[active.profile].flag} ${profileTitle(active, t)}` })}</span>}
      {active && <span className="text-muted-foreground">{effects(active, page, t).join(" · ")}</span>}
      {extras.length > 0 && (
        <span className="text-muted-foreground">{t("wb.profile.alsoTrusted", { names: extras.map((p) => t(profiles[p].title)).join(", ") })}</span>
      )}
    </div>
  )
}

/**
 * The marker of a policy field a profile sets: the profile's name when the field holds its preset, a warning when the
 * profile is on and the field was changed by hand.
 */
export function ProfileMarker({ options, path }: { options: Options; path: string }) {
  const t = useT()
  const active = activeProfile(options)
  if (!active) return null
  const expected = profilePolicy(active, path)
  if (expected === null) return null
  const name = profileTitle(active, t)
  const matches = asText(getPath(options, path)) === expected
  return (
    <span title={t(matches ? "wb.profile.markerHint" : "wb.profile.markerDiffers", { name })}
      className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium",
        matches ? "border-primary/40 bg-primary/10 text-primary" : "border-warning/50 bg-warning/10")}>
      <span aria-hidden>{profiles[active.profile].flag}</span>{matches ? t(profiles[active.profile].title) : t("wb.profile.notProfiles", { name: t(profiles[active.profile].title) })}
    </span>
  )
}
