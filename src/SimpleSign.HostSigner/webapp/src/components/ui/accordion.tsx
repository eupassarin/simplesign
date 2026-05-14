import * as React from "react"
import { cn } from "@/lib/utils"
import { ChevronDown } from "lucide-react"

interface AccordionItemProps {
  value: string
  children: React.ReactNode
  className?: string
}

interface AccordionProps {
  type?: "single" | "multiple"
  children: React.ReactNode
  className?: string
  defaultValue?: string[]
}

const AccordionContext = React.createContext<{
  openItems: string[]
  toggle: (value: string) => void
}>({ openItems: [], toggle: () => {} })

function Accordion({ type = "single", children, className, defaultValue = [] }: AccordionProps) {
  const [openItems, setOpenItems] = React.useState<string[]>(defaultValue)
  const toggle = (value: string) => {
    if (type === "single") {
      setOpenItems(prev => prev.includes(value) ? [] : [value])
    } else {
      setOpenItems(prev => prev.includes(value) ? prev.filter(i => i !== value) : [...prev, value])
    }
  }
  return (
    <AccordionContext.Provider value={{ openItems, toggle }}>
      <div className={cn("space-y-1", className)}>{children}</div>
    </AccordionContext.Provider>
  )
}

function AccordionItem({ value, children, className }: AccordionItemProps) {
  const { openItems } = React.useContext(AccordionContext)
  const isOpen = openItems.includes(value)
  return (
    <div className={cn("border rounded-lg", className)} data-state={isOpen ? "open" : "closed"}>
      {React.Children.map(children, child => {
        if (React.isValidElement(child)) {
          return React.cloneElement(child as React.ReactElement<any>, { 'data-value': value, 'data-state': isOpen ? 'open' : 'closed' })
        }
        return child
      })}
    </div>
  )
}

function AccordionTrigger({ className, children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { 'data-value'?: string; 'data-state'?: string }) {
  const { toggle } = React.useContext(AccordionContext)
  const value = props['data-value'] || ''
  return (
    <button
      type="button"
      className={cn("flex w-full items-center justify-between p-4 text-sm font-medium transition-all hover:bg-accent/50 rounded-lg", className)}
      onClick={() => toggle(value)}
    >
      {children}
      <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-200", props['data-state'] === 'open' && "rotate-180")} />
    </button>
  )
}

function AccordionContent({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement> & { 'data-value'?: string; 'data-state'?: string }) {
  if (props['data-state'] !== 'open') return null
  return (
    <div className={cn("px-4 pb-4 text-sm", className)}>
      {children}
    </div>
  )
}

export { Accordion, AccordionItem, AccordionTrigger, AccordionContent }
