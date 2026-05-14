import * as React from "react"
import { cn } from "@/lib/utils"
import { ChevronDown } from "lucide-react"

interface CollapsibleProps {
  open?: boolean
  onOpenChange?: (open: boolean) => void
  children: React.ReactNode
  className?: string
}

function Collapsible({ open, onOpenChange, children, className }: CollapsibleProps) {
  const [isOpen, setIsOpen] = React.useState(open ?? false)
  const actualOpen = open ?? isOpen
  const toggle = () => {
    const next = !actualOpen
    setIsOpen(next)
    onOpenChange?.(next)
  }
  return (
    <div className={className} data-state={actualOpen ? "open" : "closed"}>
      {React.Children.map(children, child => {
        if (React.isValidElement(child)) {
          if (child.type === CollapsibleTrigger) {
            return React.cloneElement(child as React.ReactElement<any>, { onClick: toggle, 'data-state': actualOpen ? 'open' : 'closed' })
          }
          if (child.type === CollapsibleContent) {
            return actualOpen ? child : null
          }
        }
        return child
      })}
    </div>
  )
}

const CollapsibleTrigger = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement> & { 'data-state'?: string }>(
  ({ className, children, 'data-state': dataState, ...props }, ref) => (
    <button
      ref={ref}
      type="button"
      className={cn("flex w-full items-center justify-between py-2 text-sm font-medium transition-all hover:text-foreground text-muted-foreground", className)}
      {...props}
    >
      {children}
      <ChevronDown className={cn("h-4 w-4 shrink-0 transition-transform duration-200", dataState === 'open' && "rotate-180")} />
    </button>
  )
)
CollapsibleTrigger.displayName = "CollapsibleTrigger"

function CollapsibleContent({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("overflow-hidden", className)} {...props}>
      {children}
    </div>
  )
}

export { Collapsible, CollapsibleTrigger, CollapsibleContent }
