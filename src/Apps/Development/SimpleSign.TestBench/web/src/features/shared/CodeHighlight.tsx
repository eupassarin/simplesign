import { Fragment, useMemo, useState } from "react"
import { Check, Copy } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"

/** The languages the TestBench shows code in. */
export type CodeLanguage = "csharp" | "shell" | "json"

type TokenKind = "keyword" | "type" | "string" | "comment" | "number" | "flag" | "command" | "property" | "plain"

const tokenClass: Record<TokenKind, string> = {
  keyword: "text-violet-600 dark:text-violet-400",
  type: "text-sky-700 dark:text-sky-300",
  string: "text-emerald-700 dark:text-emerald-400",
  comment: "text-muted-foreground italic",
  number: "text-amber-700 dark:text-amber-300",
  flag: "text-sky-700 dark:text-sky-300",
  command: "text-violet-600 dark:text-violet-400 font-semibold",
  property: "text-sky-700 dark:text-sky-300",
  plain: "",
}

const csharpKeywords = new Set([
  "using", "var", "new", "await", "async", "return", "if", "else", "foreach", "for", "in", "true", "false", "null", "static",
  "public", "private", "internal", "class", "record", "string", "int", "bool", "byte", "void", "this", "throw", "try", "catch",
  "finally", "namespace", "const", "readonly", "is", "not", "and", "or", "out", "ref", "default", "typeof", "nameof",
])

// One alternation per token kind, tried left to right at every position.
const csharpPattern = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|(@?\$?"(?:[^"\\\n]|\\.|"")*"|'(?:[^'\\]|\\.)')|\b(\d+(?:\.\d+)?[a-zA-Z]?)\b|([A-Za-z_][A-Za-z0-9_]*)/g
const jsonPattern = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g
const shellPattern = /(#[^\n]*)|("(?:[^"\\]|\\.)*"|'[^']*')|(\s--?[A-Za-z][\w-]*)|(^|\n)(\s*)([A-Za-z][\w.-]*)/g

function tokenize(code: string, language: CodeLanguage): { text: string; kind: TokenKind }[] {
  const tokens: { text: string; kind: TokenKind }[] = []
  let last = 0
  const push = (text: string, kind: TokenKind) => { if (text) tokens.push({ text, kind }) }
  const pattern = new RegExp(language === "csharp" ? csharpPattern : language === "json" ? jsonPattern : shellPattern)
  for (let m = pattern.exec(code); m; m = pattern.exec(code)) {
    push(code.slice(last, m.index), "plain")
    if (language === "json") {
      const [all, str, colon, num, literal] = m
      if (str) {
        push(str, colon ? "property" : "string")
        if (colon) push(colon, "plain")
      } else if (num) push(all, "number")
      else if (literal) push(all, "keyword")
    } else if (language === "csharp") {
      const [all, comment, str, num, word] = m
      if (comment) push(all, "comment")
      else if (str) push(all, "string")
      else if (num) push(all, "number")
      else if (word) push(all, csharpKeywords.has(word) ? "keyword" : /^[A-Z]/.test(word) ? "type" : "plain")
    } else {
      const [all, comment, str, flag, newline, indent, command] = m
      if (comment) push(all, "comment")
      else if (str) push(all, "string")
      else if (flag) push(all, "flag")
      else if (command) {
        push((newline ?? "") + (indent ?? ""), "plain")
        push(command, "command")
      } else push(all, "plain")
    }
    last = m.index + m[0].length
    if (m[0].length === 0) pattern.lastIndex++
  }
  push(code.slice(last), "plain")
  return tokens
}

/** Code with its language's colors and a copy button. */
export function HighlightedCode({ code, language, className }: { code: string; language: CodeLanguage; className?: string }) {
  const t = useT()
  const [copied, setCopied] = useState(false)
  const tokens = useMemo(() => tokenize(code, language), [code, language])
  return (
    <div className={cn("relative", className)}>
      <pre className="bg-muted/40 overflow-auto rounded-lg border p-4 font-mono text-xs leading-relaxed">
        <code>
          {tokens.map((tk, i) => tk.kind === "plain"
            ? <Fragment key={i}>{tk.text}</Fragment>
            : <span key={i} className={tokenClass[tk.kind]}>{tk.text}</span>)}
        </code>
      </pre>
      <Button variant="outline" size="sm" className="bg-background/80 absolute top-2 right-2 h-7" aria-label={t("common.copy")}
        onClick={() => {
          void navigator.clipboard.writeText(code)
          setCopied(true)
          toast.success(t("common.copied"))
          window.setTimeout(() => setCopied(false), 1500)
        }}>
        {copied ? <Check /> : <Copy />}
      </Button>
    </div>
  )
}
