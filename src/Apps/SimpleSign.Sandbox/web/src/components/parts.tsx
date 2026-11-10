import { useState, type ReactNode } from "react"
import { Check, ChevronRight, Copy } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { useI18n } from "@/i18n"
import { load, save } from "@/lib/storage"
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

/** Copies `value` to the clipboard, with a check mark for a moment. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  return (
    <button type="button" aria-label={`${t("common.copy")} ${label}`} title={t("common.copy")} className="text-muted-foreground hover:text-foreground shrink-0"
      onClick={() => { void navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1200) }}>
      {copied ? <Check className="text-success size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  )
}

/** A label and its value; `stacked` puts the value under the label (URLs, names), `copy` adds a copy button. */
export function KeyValue({ label, children, mono, stacked, copy }: { label: string; children: ReactNode; mono?: boolean; stacked?: boolean; copy?: string | null }) {
  const button = copy ? <CopyButton value={copy} label={label} /> : null
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

/**
 * A section folded under its title and a one-line summary; `id` keeps it open or closed across reloads.
 * Details (URLs, credentials, raw JSON) go in one, so a page shows the essentials first.
 */
export function Fold({ id, title, summary, defaultOpen = false, aside, children }: {
  id: string
  title: ReactNode
  summary?: ReactNode
  defaultOpen?: boolean
  aside?: ReactNode
  children: ReactNode
}) {
  const [open, setOpen] = useState(() => {
    const saved = load(`open.${id}`)
    return saved === null ? defaultOpen : saved === "1"
  })
  return (
    <Collapsible open={open} onOpenChange={(next) => { setOpen(next); save(`open.${id}`, next ? "1" : "0") }} className="rounded-lg border">
      <div className="flex items-center gap-2 px-4">
        <CollapsibleTrigger className="hover:text-foreground flex min-w-0 flex-1 items-center gap-2 py-3 text-left">
          <ChevronRight className={cn("text-muted-foreground size-4 shrink-0 transition-transform", open && "rotate-90")} />
          <span className="min-w-0">
            <span className="block text-sm font-medium">{title}</span>
            {summary && !open && <span className="text-muted-foreground block truncate text-xs">{summary}</span>}
          </span>
        </CollapsibleTrigger>
        {aside}
      </div>
      <CollapsibleContent className="border-t px-4 py-2">{children}</CollapsibleContent>
    </Collapsible>
  )
}
