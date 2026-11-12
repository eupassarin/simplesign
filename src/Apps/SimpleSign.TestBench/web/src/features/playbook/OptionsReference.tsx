import { useEffect, useMemo, useState } from "react"
import { Check, Copy, FileJson, FileText, Loader2, Search } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, useT } from "@/i18n"
import { api } from "@/lib/api"
import type { PolicyPreset } from "@/lib/types"
import { cn } from "@/lib/utils"
import type { Format, SchemaOption, WorkbenchSchema } from "../workbench/schema"
import { playbookApi } from "./api"
import type { PlaybookSandboxReference } from "./types"

const formats: { id: Format; label: string }[] = [
  { id: "pades", label: "PAdES" },
  { id: "cades", label: "CAdES" },
  { id: "xades", label: "XAdES" },
]

const validationExample = `{
  "kind": "validate",
  "options": {
    "fileId": "step:sign-good",
    "settings": { "trust": ["SandboxRoot"], "policyId": "preset:validation:iofe", "level": "ArchivalData" }
  },
  "expect": { "outcome": "valid" }
}`

const sandboxExample = `"sandbox": { "crl": "Down", "revoke": ["revoked"] }`

/**
 * The catalogue of what a playbook step can hold, in the UI's language: the option paths of each format (from the same
 * schema as the Sign page), the symbolic values, and what the Sandbox block can name. The Markdown version, for an LLM,
 * is linked at the bottom.
 */
export function OptionsReferenceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const t = useT()
  const { locale } = useI18n()
  const [schema, setSchema] = useState<WorkbenchSchema | null>(null)
  const [presets, setPresets] = useState<PolicyPreset[]>([])
  const [sandbox, setSandbox] = useState<PlaybookSandboxReference | null>(null)
  const [query, setQuery] = useState("")

  useEffect(() => {
    if (!open) return
    let live = true
    api.workbench.schema().then((s) => { if (live) setSchema(s) }).catch(() => undefined)
    api.policies.presets().then((p) => { if (live) setPresets(p) }).catch(() => undefined)
    playbookApi.sandbox().then((s) => { if (live) setSandbox(s) }).catch(() => undefined)
    return () => { live = false }
  }, [open, locale])

  const q = query.trim().toLowerCase()
  const matches = (o: SchemaOption) => !q || [o.path, o.title, o.summary, ...o.values.map((v) => v.value)].some((x) => x?.toLowerCase().includes(q))
  const counts = useMemo(() => Object.fromEntries(formats.map((f) => [f.id,
    schema?.options.filter((o) => o.path && o.formats.includes(f.id) && matches(o)).length ?? 0])), [schema, q])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex h-[90vh] flex-col gap-0 p-0 sm:max-w-5xl">
        <DialogHeader className="space-y-1 border-b px-6 pt-5 pb-3">
          <DialogTitle>{t("playbook.optionsRef.title")}</DialogTitle>
          <DialogDescription>{t("playbook.optionsRef.intro")}</DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="pades" className="flex min-h-0 flex-1 flex-col gap-0">
          <div className="flex flex-wrap items-center gap-3 border-b px-6 py-2">
            <TabsList variant="line">
              {formats.map((f) => (
                <TabsTrigger key={f.id} value={f.id}>{f.label}{q && <span className="text-muted-foreground ml-1 text-xs tabular-nums">{counts[f.id]}</span>}</TabsTrigger>
              ))}
              <TabsTrigger value="symbols">{t("playbook.optionsRef.symbols")}</TabsTrigger>
              <TabsTrigger value="sandbox">Sandbox</TabsTrigger>
            </TabsList>
            <div className="relative ml-auto w-64">
              <Search className="text-muted-foreground absolute top-1/2 left-2 size-3.5 -translate-y-1/2" />
              <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("playbook.optionsRef.search")} className="h-8 pl-7 text-xs" />
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-auto">
            {formats.map((f) => (
              <TabsContent key={f.id} value={f.id} className="px-6 py-4">
                {!schema
                  ? <p className="text-muted-foreground flex items-center gap-2 text-sm"><Loader2 className="size-4 animate-spin" /> {t("playbook.preparing")}</p>
                  : <FormatOptions schema={schema} format={f.id} matches={matches} />}
              </TabsContent>
            ))}

            <TabsContent value="symbols" className="space-y-4 px-6 py-4">
              <table className="w-full text-xs">
                <tbody>
                  <SymbolRow value="sandbox:SIGNER" text={t("playbook.optionsRef.symSandbox")} />
                  <SymbolRow value="sample:ID" text={t("playbook.optionsRef.symSample")} />
                  <SymbolRow value="cades-sample:ID · xades-sample:ID" text={t("playbook.optionsRef.symFormatSample")} />
                  <SymbolRow value="preset:signing:NAME · preset:validation:NAME" text={t("playbook.optionsRef.symPreset")}
                    extra={presets.map((p) => p.id)} />
                  <SymbolRow value="step:ID" text={t("playbook.optionsRef.symStep")} />
                </tbody>
              </table>
              <div className="space-y-1">
                <p className="text-xs font-semibold uppercase">{t("playbook.optionsRef.validationStep")}</p>
                <p className="text-muted-foreground text-xs">{t("playbook.optionsRef.validationHint")}</p>
                <pre className="bg-muted/40 overflow-auto rounded-md border p-3 font-mono text-xs">{validationExample}</pre>
              </div>
            </TabsContent>

            <TabsContent value="sandbox" className="space-y-4 px-6 py-4">
              <p className="text-muted-foreground text-xs">{t("playbook.optionsRef.sandboxIntro")}</p>
              <pre className="bg-muted/40 overflow-auto rounded-md border p-3 font-mono text-xs">{sandboxExample}</pre>
              {sandbox && (
                <>
                  <div className="space-y-1">
                    <p className="text-xs font-semibold uppercase">{t("playbook.optionsRef.faults")}</p>
                    <table className="w-full text-xs">
                      <tbody>
                        {Object.entries(sandbox.faults).map(([service, names]) => (
                          <tr key={service} className="border-b last:border-0">
                            <td className="w-40 py-1.5 pr-3 align-top"><Path value={`sandbox.${service}`} /></td>
                            <td className="py-1.5"><Chips values={names} /></td>
                          </tr>
                        ))}
                        <tr>
                          <td className="py-1.5 pr-3 align-top"><Path value="sandbox.revoke" /></td>
                          <td className="text-muted-foreground py-1.5">{t("playbook.optionsRef.revokeHint")}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  {!sandbox.connected
                    ? <p className="bg-warning/10 border-warning/40 rounded-md border px-3 py-2 text-xs">{t("playbook.optionsRef.notConnected")}</p>
                    : (
                      <div className="grid gap-4 md:grid-cols-2">
                        <IdList title={t("playbook.optionsRef.signers")} hint="sandbox:ID" ids={sandbox.signers} prefix="sandbox:" />
                        <IdList title={t("playbook.optionsRef.certificates")} hint="sandbox.revoke" ids={sandbox.certificates} />
                      </div>
                    )}
                </>
              )}
            </TabsContent>
          </div>
        </Tabs>
        <div className="flex items-center gap-2 border-t px-6 py-3">
          <p className="text-muted-foreground min-w-0 flex-1 text-xs">{t("playbook.optionsRef.forLlm")}</p>
          <Button variant="outline" size="sm" asChild><a href={playbookApi.optionsUrl} target="_blank" rel="noreferrer"><FileText /> {t("playbook.optionsRef.markdown")}</a></Button>
          <Button variant="outline" size="sm" asChild><a href={playbookApi.schemaUrl} target="_blank" rel="noreferrer"><FileJson /> {t("playbook.schema")}</a></Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function FormatOptions({ schema, format, matches }: { schema: WorkbenchSchema; format: Format; matches: (o: SchemaOption) => boolean }) {
  const t = useT()
  const groups = schema.sections
    .map((s) => ({ section: s, options: schema.options.filter((o) => o.section === s.id && o.path && o.formats.includes(format) && matches(o)) }))
    .filter((g) => g.options.length > 0)
  if (groups.length === 0) return <p className="text-muted-foreground text-sm">{t("playbook.optionsRef.noMatch")}</p>
  return (
    <div className="space-y-5">
      {groups.map(({ section, options }) => (
        <div key={section.id}>
          <p className="mb-1 text-xs font-semibold uppercase">{section.title}</p>
          <table className="w-full text-xs">
            <tbody>
              {options.map((o) => (
                <tr key={o.id} className="border-b align-top last:border-0">
                  <td className="w-[34%] py-1.5 pr-3"><Path value={o.path!} /></td>
                  <td className="py-1.5 pr-3">
                    <span className="font-medium">{o.title}</span>
                    <span className="text-muted-foreground"> — {o.summary}</span>
                  </td>
                  <td className="w-[30%] py-1.5">
                    {o.values.length > 0
                      ? <Chips values={o.values.map((v) => v.value)} titles={o.values.map((v) => v.title)} />
                      : <span className="text-muted-foreground font-mono text-[11px]">{o.kind}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  )
}

function Path({ value }: { value: string }) {
  const t = useT()
  const [copied, setCopied] = useState(false)
  return (
    <span className="group inline-flex items-center gap-1">
      <code className="bg-muted rounded px-1 py-0.5 font-mono text-[11px] break-all">{value}</code>
      <button aria-label={t("common.copy")} title={t("common.copy")}
        className="text-muted-foreground hover:text-foreground opacity-0 group-hover:opacity-100 focus-visible:opacity-100"
        onClick={() => {
          void navigator.clipboard.writeText(value)
          setCopied(true)
          toast.success(t("common.copied"))
          window.setTimeout(() => setCopied(false), 1500)
        }}>
        {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
      </button>
    </span>
  )
}

function Chips({ values, titles }: { values: string[]; titles?: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((v, i) => (
        <code key={i} title={titles?.[i] && titles[i] !== v ? titles[i] : undefined}
          className={cn("rounded border px-1 font-mono text-[11px]", titles?.[i] && titles[i] !== v && "cursor-help")}>{v === "" ? '""' : v}</code>
      ))}
    </span>
  )
}

function SymbolRow({ value, text, extra }: { value: string; text: string; extra?: string[] }) {
  return (
    <tr className="border-b align-top last:border-0">
      <td className="w-[38%] py-2 pr-3 font-mono text-[11px]">{value}</td>
      <td className="py-2">
        <p>{text}</p>
        {extra && extra.length > 0 && <div className="mt-1"><Chips values={extra} /></div>}
      </td>
    </tr>
  )
}

function IdList({ title, hint, ids, prefix = "" }: { title: string; hint: string; ids: { id: string; title: string }[]; prefix?: string }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-semibold uppercase">{title} <span className="text-muted-foreground font-mono font-normal normal-case">{hint}</span></p>
      <table className="w-full text-xs">
        <tbody>
          {ids.map((x) => (
            <tr key={x.id} className="border-b last:border-0">
              <td className="py-1 pr-3"><Path value={prefix + x.id} /></td>
              <td className="text-muted-foreground py-1">{x.title}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
