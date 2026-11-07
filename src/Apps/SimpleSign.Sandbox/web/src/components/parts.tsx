import { useState, type ReactNode } from "react"
import { Check, Copy } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

/** A titled block of the page. */
export function Section({ title, description, aside, children }: { title: ReactNode; description?: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div className="space-y-0.5">
          <h2 className="text-base font-semibold">{title}</h2>
          {description && <p className="text-muted-foreground max-w-3xl text-sm">{description}</p>}
        </div>
        {aside}
      </div>
      {children}
    </section>
  )
}

/** A label and its value; `stacked` puts the value under the label (URLs, names), `copy` adds a copy button. */
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
        <span className={cn("min-w-0 truncate text-right", mono && "font-mono text-xs")}>{children}</span>
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
