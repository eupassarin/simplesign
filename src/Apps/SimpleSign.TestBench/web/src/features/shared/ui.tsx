import { useState, type ReactNode } from "react"
import { AlertTriangle, BookOpen, Check, CircleAlert, Code2, Copy, Info, Lock } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"
import type { OptionIssue, OptionState } from "@/lib/types"
import { useT } from "@/i18n"
import { useCatalog } from "./catalog"

/** The "i" next to an option: summary, details, the standard and the library API. */
export function Explain({ id, className }: { id: string; className?: string }) {
  const catalog = useCatalog()
  const t = useT()
  const info = catalog[id]
  if (!info) return null
  return (
    <HoverCard openDelay={120} closeDelay={80}>
      <HoverCardTrigger asChild>
        <button
          type="button"
          aria-label={t("common.about", { name: info.title })}
          className={cn("text-muted-foreground hover:text-foreground inline-flex size-4 items-center justify-center rounded-full transition-colors", className)}
          onClick={(e) => e.preventDefault()}
        >
          <Info className="size-3.5" />
        </button>
      </HoverCardTrigger>
      <HoverCardContent className="w-96 space-y-2 text-sm" align="start">
        <p className="font-medium">{info.title}</p>
        <p className="text-muted-foreground">{info.summary}</p>
        {info.details && <p className="leading-relaxed">{info.details}</p>}
        {(info.spec || info.api) && (
          <div className="space-y-1 border-t pt-2 text-xs">
            {info.spec && (
              <p className="text-muted-foreground flex items-start gap-1.5">
                <BookOpen className="mt-0.5 size-3 shrink-0" /> {info.spec}
              </p>
            )}
            {info.api && (
              <p className="flex items-start gap-1.5">
                <Code2 className="text-muted-foreground mt-0.5 size-3 shrink-0" />
                <code className="font-mono text-[11px] break-all">{info.api}</code>
              </p>
            )}
          </div>
        )}
      </HoverCardContent>
    </HoverCard>
  )
}

/** A selectable card for a mutually exclusive choice. Disabled cards say why. */
export function ChoiceCard({
  selected,
  onSelect,
  title,
  description,
  infoId,
  state,
  badge,
  icon,
  children,
}: {
  selected: boolean
  onSelect: () => void
  title: ReactNode
  description?: ReactNode
  infoId?: string
  state?: OptionState
  badge?: ReactNode
  icon?: ReactNode
  children?: ReactNode
}) {
  if (state && !state.visible) return null
  const disabled = !!state?.disabled
  return (
    <div
      role="radio"
      aria-checked={selected}
      aria-disabled={disabled}
      tabIndex={disabled ? -1 : 0}
      onClick={() => !disabled && onSelect()}
      onKeyDown={(e) => {
        if (!disabled && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault()
          onSelect()
        }
      }}
      className={cn(
        "group relative flex cursor-pointer flex-col gap-1.5 rounded-lg border p-3.5 text-left transition-all outline-none",
        "focus-visible:ring-ring/50 focus-visible:ring-[3px]",
        selected ? "border-primary bg-accent/60 shadow-xs ring-primary/20 ring-1" : "hover:border-foreground/25 hover:bg-accent/30",
        disabled && "cursor-not-allowed opacity-55 hover:border-border hover:bg-transparent",
      )}
    >
      <div className="flex items-start gap-2.5">
        {icon && <div className={cn("text-muted-foreground mt-0.5", selected && "text-foreground")}>{icon}</div>}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="text-sm leading-tight font-medium">{title}</span>
            {infoId && <Explain id={infoId} />}
            {badge}
          </div>
          {description && <p className="text-muted-foreground mt-1 text-xs leading-relaxed">{description}</p>}
        </div>
        <span
          className={cn(
            "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border",
            selected ? "border-primary bg-primary" : "border-input",
          )}
        >
          {selected && <span className="bg-primary-foreground size-1.5 rounded-full" />}
        </span>
      </div>
      {disabled && (
        <p className="text-muted-foreground flex items-start gap-1.5 text-xs">
          <Lock className="mt-0.5 size-3 shrink-0" />
          {state!.disabled}
        </p>
      )}
      {selected && children && <div className="mt-2" onClick={(e) => e.stopPropagation()}>{children}</div>}
    </div>
  )
}

/** A labelled field with an optional explanation and description. */
export function Field({
  label,
  infoId,
  description,
  children,
  className,
  htmlFor,
}: {
  label: ReactNode
  infoId?: string
  description?: ReactNode
  children: ReactNode
  className?: string
  htmlFor?: string
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-center gap-1.5">
        <Label htmlFor={htmlFor} className="text-sm">
          {label}
        </Label>
        {infoId && <Explain id={infoId} />}
      </div>
      {children}
      {description && <p className="text-muted-foreground text-xs leading-relaxed">{description}</p>}
    </div>
  )
}

/** A switch row: label + explanation on the left, switch on the right. Hidden or disabled by the rules. */
export function ToggleRow({
  checked,
  onChange,
  label,
  description,
  infoId,
  state,
}: {
  checked: boolean
  onChange: (value: boolean) => void
  label: ReactNode
  description?: ReactNode
  infoId?: string
  state?: OptionState
}) {
  if (state && !state.visible) return null
  const disabled = !!state?.disabled
  return (
    <div className={cn("flex items-start justify-between gap-4 rounded-lg border p-3.5", disabled && "opacity-60")}>
      <div className="space-y-1">
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-medium">{label}</span>
          {infoId && <Explain id={infoId} />}
        </div>
        {description && <p className="text-muted-foreground text-xs leading-relaxed">{description}</p>}
        {disabled && (
          <p className="text-muted-foreground flex items-start gap-1.5 text-xs">
            <Lock className="mt-0.5 size-3 shrink-0" /> {state!.disabled}
          </p>
        )}
        {state?.note && <p className="text-muted-foreground text-xs italic">{state.note}</p>}
      </div>
      <Switch checked={checked && !disabled} onCheckedChange={onChange} disabled={disabled} />
    </div>
  )
}

export function Section({ title, description, infoId, children, aside }: { title: ReactNode; description?: ReactNode; infoId?: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="space-y-3">
      <div className="flex items-end justify-between gap-4">
        <div className="space-y-0.5">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold">
            {title}
            {infoId && <Explain id={infoId} />}
          </h3>
          {description && <p className="text-muted-foreground text-xs leading-relaxed">{description}</p>}
        </div>
        {aside}
      </div>
      {children}
    </section>
  )
}

export function IssueList({ issues }: { issues: OptionIssue[] }) {
  if (issues.length === 0) return null
  return (
    <ul className="space-y-2">
      {issues.map((issue, i) => (
        <li
          key={i}
          className={cn(
            "flex items-start gap-2 rounded-md border px-3 py-2 text-xs leading-relaxed",
            issue.severity === "Error" && "border-destructive/30 bg-destructive/5 text-destructive",
            issue.severity === "Warning" && "border-warning/40 bg-warning/10",
            issue.severity === "Info" && "bg-muted/50 text-muted-foreground",
          )}
        >
          {issue.severity === "Error" ? (
            <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
          ) : issue.severity === "Warning" ? (
            <AlertTriangle className="text-warning mt-0.5 size-3.5 shrink-0" />
          ) : (
            <Info className="mt-0.5 size-3.5 shrink-0" />
          )}
          <span>{issue.message}</span>
        </li>
      ))}
    </ul>
  )
}

/**
 * A label and its value. In a row for short values; `stacked` puts the value under the label and
 * lets it wrap (URLs, distinguished names, OIDs, hex), so nothing is cut. `copy` adds a copy button.
 */
export function KeyValue({ label, children, mono, stacked, copy }: { label: string; children: ReactNode; mono?: boolean; stacked?: boolean; copy?: string | null }) {
  const [copied, setCopied] = useState(false)
  const button = copy ? (
    <button type="button" aria-label={`Copy ${label}`} className="text-muted-foreground hover:text-foreground shrink-0"
      onClick={() => { void navigator.clipboard.writeText(copy); setCopied(true); setTimeout(() => setCopied(false), 1200) }}>
      {copied ? <Check className="text-success size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  ) : null
  if (stacked) {
    return (
      <div className="space-y-0.5 py-1.5">
        <span className="text-muted-foreground block text-xs">{label}</span>
        <span className="flex items-start gap-2">
          <span className={cn("min-w-0 flex-1 text-sm break-all", mono && "font-mono text-xs leading-relaxed")}>{children}</span>
          {button}
        </span>
      </div>
    )
  }
  return (
    <div className="flex items-baseline justify-between gap-3 py-1 text-sm">
      <span className="text-muted-foreground shrink-0 text-xs">{label}</span>
      <span className="flex min-w-0 items-baseline gap-2">
        <span className={cn("min-w-0 truncate text-right", mono && "font-mono text-xs")} title={typeof children === "string" ? children : undefined}>{children}</span>
        {button}
      </span>
    </div>
  )
}

export function Pill({ children, tone = "default" }: { children: ReactNode; tone?: "default" | "success" | "warning" | "danger" | "info" }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "font-normal",
        tone === "success" && "border-success/40 bg-success/10 text-success",
        tone === "warning" && "border-warning/50 bg-warning/10",
        tone === "danger" && "border-destructive/40 bg-destructive/10 text-destructive",
        tone === "info" && "border-info/40 bg-info/10 text-info",
      )}
    >
      {children}
    </Badge>
  )
}
