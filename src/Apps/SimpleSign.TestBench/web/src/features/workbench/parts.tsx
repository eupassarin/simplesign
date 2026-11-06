import type { ReactNode } from "react"
import { BookOpen, Code2, Info, Lock } from "lucide-react"
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card"
import { useT } from "@/i18n"
import type { OptionState } from "@/lib/types"
import { cn } from "@/lib/utils"
import type { StandardRef } from "./schema"

/** What an explanation shows: the words, the clauses and the library call. */
export interface Explanation {
  title: string
  summary?: string | null
  details?: string | null
  standards: StandardRef[]
  api?: string | null
}

/** "ETSI EN 319 142-1" + "§6.3 PAdES-B-B" → "EN 319 142-1 §6.3". */
export function shortRef(ref: StandardRef) {
  const document = ref.document.replace(/^ETSI /, "").replace(/^W3C /, "")
  const clause = /^§[\w.–-]+/.exec(ref.clause)?.[0]
  return clause ? `${document} ${clause}` : document
}

/** The colors of each trust framework, so national options stand out from the generic ETSI ones. */
export const frameworkTone: Record<string, { chip: string; border: string; tag: string; label: string }> = {
  brazil: {
    chip: "border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
    border: "border-l-emerald-500 bg-emerald-500/[0.04]",
    tag: "border-emerald-500/50 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
    label: "BR",
  },
}

export function FrameworkTag({ framework }: { framework?: string | null }) {
  const tone = framework ? frameworkTone[framework] : undefined
  if (!tone) return null
  return <span className={cn("rounded border px-1 py-px text-[10px] leading-none font-semibold tracking-wide", tone.tag)}>{tone.label}</span>
}

/** The clause of the standard that defines an option, as a small badge; hover for every reference and the library call. */
export function StandardBadge({ explanation, className }: { explanation: Explanation; className?: string }) {
  const t = useT()
  const first = explanation.standards[0]
  if (!first && !explanation.api && !explanation.details) return null
  return (
    <HoverCard openDelay={120} closeDelay={80}>
      <HoverCardTrigger asChild>
        <button type="button" onClick={(e) => e.stopPropagation()} aria-label={t("common.about", { name: explanation.title })}
          className={cn("text-muted-foreground hover:text-foreground hover:border-foreground/30 inline-flex max-w-full items-center gap-1 rounded border px-1.5 py-px font-mono text-[10px] leading-4 transition-colors", className)}>
          {first ? <><BookOpen className="size-3 shrink-0" /><span className="truncate">{shortRef(first)}</span>{explanation.standards.length > 1 && <span className="opacity-70">+{explanation.standards.length - 1}</span>}</>
            : <Info className="size-3" />}
        </button>
      </HoverCardTrigger>
      <HoverCardContent className="w-[26rem] space-y-2 text-sm" align="start" onClick={(e) => e.stopPropagation()}>
        <p className="font-medium">{explanation.title}</p>
        {explanation.summary && <p className="text-muted-foreground">{explanation.summary}</p>}
        {explanation.details && <p className="leading-relaxed">{explanation.details}</p>}
        {(explanation.standards.length > 0 || explanation.api) && (
          <div className="space-y-1.5 border-t pt-2 text-xs">
            {explanation.standards.map((ref) => (
              <p key={ref.document + ref.clause} className="flex items-start gap-1.5">
                <BookOpen className="text-muted-foreground mt-0.5 size-3 shrink-0" />
                <span><span className="font-medium">{ref.document}</span>{ref.clause && <span className="text-muted-foreground"> · {ref.clause}</span>}</span>
              </p>
            ))}
            {explanation.api && (
              <p className="flex items-start gap-1.5">
                <Code2 className="text-muted-foreground mt-0.5 size-3 shrink-0" />
                <code className="font-mono text-[11px] break-all">{explanation.api}</code>
              </p>
            )}
          </div>
        )}
      </HoverCardContent>
    </HoverCard>
  )
}

/** The frame of one option: label, clause, framework tag, summary, the editor, and why it is locked. */
export function OptionRow({ explanation, framework, state, missing, inline, children }: {
  explanation: Explanation
  framework?: string | null
  state?: OptionState
  /** The standard defines it and SimpleSign does not implement it. */
  missing?: boolean
  /** The editor sits on the right of the label (switches) instead of below it. */
  inline?: boolean
  children?: ReactNode
}) {
  const t = useT()
  const tone = framework ? frameworkTone[framework] : undefined
  const head = (
    <div className="min-w-0 space-y-0.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className={cn("text-sm font-medium", missing && "text-muted-foreground")}>{explanation.title}</span>
        <FrameworkTag framework={framework} />
        <StandardBadge explanation={explanation} />
        {missing && <span className="rounded border border-dashed px-1.5 py-px text-[10px] leading-4">{t("wb.notInLibrary")}</span>}
      </div>
      {explanation.summary && <p className="text-muted-foreground text-xs leading-relaxed">{explanation.summary}</p>}
    </div>
  )
  return (
    <div className={cn("space-y-2 py-3", tone && "-mx-3 border-l-2 px-3", tone?.border, missing && "opacity-70")}>
      {inline ? <div className="flex items-start justify-between gap-4">{head}<div className="shrink-0 pt-0.5">{children}</div></div> : <>{head}{children}</>}
      {state?.disabled && <p className="text-muted-foreground flex items-start gap-1.5 text-xs"><Lock className="mt-0.5 size-3 shrink-0" />{state.disabled}</p>}
      {state?.note && <p className="text-muted-foreground text-xs italic">{state.note}</p>}
    </div>
  )
}
