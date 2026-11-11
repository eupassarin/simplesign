import { createContext, useContext, useEffect, useState } from "react"
import { Download, Eye, FileText, Lock, Plus, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import type { CadesSample, OptionState, PolicyKind, PolicyPreset, SampleDocument, TimestampChoice, XmlSample } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CredentialPicker } from "../credentials/CredentialPicker"
import { PoliciesPage } from "../policies/PoliciesPage"
import { TsaPicker } from "../shared/TsaPicker"
import { Pill } from "../shared/ui"
import { UploadButton } from "../shared/UploadButton"
import { OptionRow, StandardBadge, type Explanation } from "./parts"
import { asText, getPath, type Options, type SchemaOption, type SchemaValue } from "./schema"
import { useWorkbench } from "./state"

const explain = (o: SchemaOption | SchemaValue): Explanation =>
  ({ title: o.title, summary: o.summary, details: o.details, standards: o.standards, api: o.api })

/**
 * Where an option reads and writes its value. Without a scope, options edit the signing options
 * of the current format; the Validate task gives its own (the trust settings).
 */
export const OptionScope = createContext<{ options: Options; set: (path: string, value: unknown) => void } | null>(null)

/** One option of the schema, with the editor its kind asks for. */
export function OptionField({ option }: { option: SchemaOption }) {
  const workbench = useWorkbench()
  const scope = useContext(OptionScope)
  const { options, set } = scope ?? workbench
  const state: (key: string) => OptionState = scope ? () => ({ visible: true }) : workbench.state
  const t = useT()
  if (option.support === "notInLibrary") {
    return <OptionRow explanation={explain(option)} missing inline><Switch checked={false} disabled aria-label={option.title} /></OptionRow>
  }

  const path = option.path ?? ""
  const value = getPath(options, path)
  const optionState = option.stateKey ? state(option.stateKey) : undefined
  const locked = !!optionState?.disabled
  const row = { explanation: explain(option), state: optionState }
  const text = (v: string) => set(path, v === "" ? null : v)

  switch (option.kind) {
    case "info":
      return <OptionRow {...row} />
    case "toggle":
      return <OptionRow {...row} inline><Switch checked={value === true && !locked} disabled={locked} onCheckedChange={(v) => set(path, v)} aria-label={option.title} /></OptionRow>
    case "choice":
      return <OptionRow {...row}><Choice option={option} value={asText(value)} locked={locked} onChange={(v) => set(path, v === "" && value === null ? null : v || null)} /></OptionRow>
    case "text":
      return <OptionRow {...row}><Input value={asText(value)} disabled={locked} onChange={(e) => text(e.target.value)} className={/oid|uri|hash|url/i.test(path) ? "font-mono text-xs" : undefined} /></OptionRow>
    case "number":
      return <OptionRow {...row}><Input type="number" className="max-w-40" value={asText(value)} disabled={locked}
        onChange={(e) => set(path, e.target.value === "" ? null : Number(e.target.value))} /></OptionRow>
    case "datetime":
      return <OptionRow {...row}><Input type="datetime-local" className="max-w-64" value={typeof value === "string" ? value.slice(0, 16) : ""} disabled={locked}
        onChange={(e) => set(path, e.target.value ? new Date(e.target.value).toISOString() : null)} /></OptionRow>
    case "lines":
      return <OptionRow {...row}><Textarea rows={3} value={Array.isArray(value) ? value.join("\n") : ""} disabled={locked}
        onChange={(e) => set(path, e.target.value.split("\n").map((l) => l.trimEnd()).filter((l, i, all) => l !== "" || i < all.length - 1))} /></OptionRow>
    case "color":
      return (
        <OptionRow {...row}>
          <div className="flex items-center gap-2">
            <input type="color" className="h-9 w-10 cursor-pointer rounded-md border bg-transparent p-1" value={asText(value) || "#ffffff"} onChange={(e) => set(path, e.target.value)} />
            <Input className="max-w-32 font-mono text-xs" value={asText(value)} placeholder="—" onChange={(e) => text(e.target.value)} />
            {!!value && <Button variant="ghost" size="sm" onClick={() => set(path, null)}>{t("wb.clear")}</Button>}
          </div>
        </OptionRow>
      )
    case "upload": {
      // The JSON policies: the one in use (the library's default until a file is uploaded), to view or change.
      const policy = path === "signingPolicyId" ? "signing" : path === "validation.policyId" ? "validation" : null
      if (policy) {
        return <OptionRow {...row}><PolicyField kind={policy} uploadId={typeof value === "string" ? value : null} onChange={(id) => set(path, id)} /></OptionRow>
      }
      return (
        <OptionRow {...row}>
          <div className="flex flex-wrap items-center gap-2">
            <UploadButton label={t("wb.chooseFile")} accept="*/*" onUploaded={(f) => set(path, f.id)} />
            {!!value && <><Pill tone="success">{t("wb.uploaded")}</Pill><Button variant="ghost" size="sm" onClick={() => set(path, null)}>{t("wb.clear")}</Button></>}
          </div>
        </OptionRow>
      )
    }
    case "tsa":
      return <OptionRow {...row}><Tsa value={value as TimestampChoice} onChange={(v) => set(path, v)} /></OptionRow>
    case "trust":
      return <OptionRow {...row}><Trust option={option} value={Array.isArray(value) ? (value as string[]) : []} onChange={(v) => set(path, v)} /></OptionRow>
    case "keyValues":
      return <OptionRow {...row}><KeyValues value={Array.isArray(value) ? (value as { key: string; value: string }[]) : []} onChange={(v) => set(path, v)} /></OptionRow>
    case "document":
      return <OptionRow {...row}><DocumentPicker /></OptionRow>
    case "data":
      return <OptionRow {...row}><DataPicker path={path} kind="data" /></OptionRow>
    case "existingSignature":
      return <OptionRow {...row}><DataPicker path={path} kind="signature" /></OptionRow>
    case "existingField":
      return <OptionRow {...row}><ExistingField value={asText(value)} onChange={(v) => set(path, v)} /></OptionRow>
    case "credential":
      return <OptionRow {...row}><Credential /></OptionRow>
    default:
      return null
  }
}

function Choice({ option, value, locked, onChange }: { option: SchemaOption; value: string; locked: boolean; onChange: (value: string) => void }) {
  const { state, visibleValues } = useWorkbench()
  const values = visibleValues(option)
  const valueState = (v: SchemaValue): OptionState | undefined => (option.valueStateKey ? state(`${option.valueStateKey}.${v.value}`) : undefined)
  const asCards = values.length <= 5 && values.some((v) => v.summary)
  if (!asCards) {
    return (
      <Select value={value === "" ? "__none" : value} disabled={locked} onValueChange={(v) => onChange(v === "__none" ? "" : v)}>
        <SelectTrigger className="w-full max-w-sm"><SelectValue /></SelectTrigger>
        <SelectContent>
          {values.map((v) => (
            <SelectItem key={v.value} value={v.value === "" ? "__none" : v.value} disabled={!!valueState(v)?.disabled}>
              {v.title}{valueState(v)?.disabled ? ` — ${valueState(v)!.disabled}` : ""}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    )
  }
  return (
    <div role="radiogroup" aria-label={option.title} className={cn("grid gap-2", values.length >= 4 ? "sm:grid-cols-2" : values.length === 3 ? "sm:grid-cols-3" : "sm:grid-cols-2")}>
      {values.map((v) => {
        const s = valueState(v)
        const disabled = locked || !!s?.disabled
        const selected = value === v.value
        return (
          <div key={v.value} role="radio" aria-checked={selected} aria-disabled={disabled} tabIndex={disabled ? -1 : 0}
            onClick={() => !disabled && onChange(v.value)}
            onKeyDown={(e) => { if (!disabled && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onChange(v.value) } }}
            className={cn("flex cursor-pointer flex-col gap-1 rounded-lg border p-2.5 text-left transition-all outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
              selected ? "border-primary bg-accent/60 ring-primary/20 ring-1" : "hover:border-foreground/25 hover:bg-accent/30",
              disabled && "cursor-not-allowed opacity-55 hover:border-border hover:bg-transparent")}>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-sm leading-tight font-medium">{v.title}</span>
              <StandardBadge explanation={explain(v)} className="ml-auto" />
            </div>
            {v.summary && <p className="text-muted-foreground text-xs leading-snug">{v.summary}</p>}
            {s?.disabled && <p className="text-muted-foreground flex items-start gap-1 text-[11px]"><Lock className="mt-0.5 size-3 shrink-0" />{s.disabled}</p>}
          </div>
        )
      })}
    </div>
  )
}

function Tsa({ value, onChange }: { value: TimestampChoice; onChange: (value: TimestampChoice) => void }) {
  const { state, env } = useWorkbench()
  return <TsaPicker value={value} onChange={onChange} state={state} env={env} />
}

function Trust({ option, value, onChange }: { option: SchemaOption; value: string[]; onChange: (value: string[]) => void }) {
  const { visibleValues } = useWorkbench()
  return (
    <div className="space-y-2">
      {visibleValues(option).map((v) => (
        <label key={v.value} className="flex items-start gap-2 text-sm">
          <Checkbox className="mt-0.5" checked={value.includes(v.value)}
            onCheckedChange={(on) => onChange(on === true ? [...value, v.value] : value.filter((x) => x !== v.value))} />
          <span>
            <span className="flex items-center gap-1.5">{v.title}</span>
            {v.summary && <span className="text-muted-foreground block text-xs">{v.summary}</span>}
          </span>
        </label>
      ))}
    </div>
  )
}

function KeyValues({ value, onChange }: { value: { key: string; value: string }[]; onChange: (value: { key: string; value: string }[]) => void }) {
  const t = useT()
  const edit = (i: number, patch: Partial<{ key: string; value: string }>) => onChange(value.map((e, n) => (n === i ? { ...e, ...patch } : e)))
  return (
    <div className="space-y-2">
      {value.map((entry, i) => (
        <div key={i} className="flex gap-2">
          <Input className="max-w-40" placeholder="Title" value={entry.key} onChange={(e) => edit(i, { key: e.target.value })} />
          <Input value={entry.value} onChange={(e) => edit(i, { value: e.target.value })} />
          <Button variant="ghost" size="icon" aria-label={t("wb.remove")} onClick={() => onChange(value.filter((_, n) => n !== i))}><Trash2 /></Button>
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={() => onChange([...value, { key: "", value: "" }])}><Plus /> {t("wb.add")}</Button>
    </div>
  )
}

/** The PDF to sign: a sample or an upload, with the facts that decide what can be chosen next. */
function DocumentPicker() {
  const { options, patch, evaluation } = useWorkbench()
  const t = useT()
  const [samples, setSamples] = useState<SampleDocument[]>([])
  const [uploaded, setUploaded] = useState<{ id: string; fileName: string } | null>(null)
  const current = asText(options.documentId)
  useEffect(() => {
    api.samples().then((list) => {
      setSamples(list)
      if (!current && list.length > 0) patch({ documentId: list[0].facts.id })
    }).catch(() => setSamples([]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const choose = (id: string) => {
    const facts = samples.find((s) => s.facts.id === id)?.facts
    patch({ documentId: id, existingFieldName: facts?.emptyFields[0] ?? null, fieldMode: "New", certification: "None" })
  }
  const facts = evaluation?.document
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={current} onValueChange={choose}>
          <SelectTrigger className="w-full max-w-sm"><SelectValue placeholder={t("wb.pickDocument")} /></SelectTrigger>
          <SelectContent>
            {samples.map((s) => <SelectItem key={s.facts.id} value={s.facts.id}>{s.title}</SelectItem>)}
            {uploaded && <SelectItem value={uploaded.id}>{uploaded.fileName}</SelectItem>}
          </SelectContent>
        </Select>
        <input id="wb-pdf-upload" type="file" accept="application/pdf,.pdf" hidden onChange={async (e) => {
          const file = e.target.files?.[0]
          if (!file) return
          const result = await api.uploadDocument(file)
          setUploaded({ id: result.id, fileName: result.fileName })
          patch({ documentId: result.id, existingFieldName: null, fieldMode: "New" })
          e.target.value = ""
        }} />
        <Button variant="outline" size="sm" onClick={() => document.getElementById("wb-pdf-upload")?.click()}><FileText /> {t("wb.uploadPdf")}</Button>
        {current && <Button variant="ghost" size="sm" asChild><a href={api.fileUrl(current)} target="_blank" rel="noreferrer">{t("wb.open")}</a></Button>}
      </div>
      {samples.find((s) => s.facts.id === current)?.description && <p className="text-muted-foreground text-xs">{samples.find((s) => s.facts.id === current)!.description}</p>}
      {facts && (
        <div className="flex flex-wrap gap-1.5">
          <Pill>PDF {facts.pdfVersion}</Pill>
          {facts.isPdfA && <Pill tone="info">PDF/{facts.pdfALevel.replace("A", "A-")}</Pill>}
          {facts.docMdpLevel > 0 && <Pill tone={facts.docMdpLevel === 1 ? "danger" : "warning"}>DocMDP P={facts.docMdpLevel}</Pill>}
          <Pill>{t("wb.signatures", { n: facts.signatures.length })}</Pill>
          {facts.emptyFields.length > 0 && <Pill>{t("wb.emptyFields", { n: facts.emptyFields.length })}</Pill>}
          {facts.isEncrypted && <Pill tone="warning">{t("wb.encrypted")}</Pill>}
        </div>
      )}
    </div>
  )
}

/** The file to sign (CAdES, XAdES) or the existing CMS signature to co-sign or countersign. */
function DataPicker({ path, kind }: { path: string; kind: "data" | "signature" }) {
  const { format, options, set, patch } = useWorkbench()
  const t = useT()
  const [cades, setCades] = useState<CadesSample[]>([])
  const [xml, setXml] = useState<XmlSample[]>([])
  const [uploaded, setUploaded] = useState<{ id: string; fileName: string } | null>(null)
  const current = asText(getPath(options, path))
  useEffect(() => {
    if (format === "cades") api.cades.samples().then(setCades).catch(() => setCades([]))
    else api.xml.samples().then(setXml).catch(() => setXml([]))
  }, [format])
  const list: { id: string; title: string; description: string; apply?: Record<string, unknown> }[] = format === "cades"
    ? cades.filter((s) => s.kind === kind).map((s) => ({ id: s.fileId, title: s.title, description: s.description, apply: kind === "signature" && s.dataId ? { dataId: s.dataId } : undefined }))
    : xml.filter((s) => s.kind === "data").map((s) => ({ id: s.fileId, title: s.title, description: s.description }))
  useEffect(() => {
    if (kind === "data" && list.length > 0 && !list.some((s) => s.id === current) && uploaded?.id !== current) {
      patch({ [path]: list[0].id, ...list[0].apply })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.map((s) => s.id).join(",")])
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={current} onValueChange={(id) => patch({ [path]: id, ...list.find((s) => s.id === id)?.apply })}>
          <SelectTrigger className="w-full max-w-sm"><SelectValue placeholder={t("wb.pickFile")} /></SelectTrigger>
          <SelectContent>
            {list.map((s) => <SelectItem key={s.id} value={s.id}>{s.title}</SelectItem>)}
            {uploaded && <SelectItem value={uploaded.id}>{uploaded.fileName}</SelectItem>}
          </SelectContent>
        </Select>
        <UploadButton label={t("wb.chooseFile")} accept={format === "xades" ? ".xml,text/xml,application/xml" : kind === "signature" ? ".p7s,.p7m,.p7b,.der" : "*/*"}
          onUploaded={(f) => { setUploaded(f); set(path, f.id) }} />
        {current && <Button variant="ghost" size="sm" asChild><a href={api.fileUrl(current, true)}>{t("common.download")}</a></Button>}
      </div>
      {list.find((s) => s.id === current)?.description && <p className="text-muted-foreground text-xs">{list.find((s) => s.id === current)!.description}</p>}
    </div>
  )
}

function ExistingField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const { evaluation } = useWorkbench()
  const t = useT()
  const fields = evaluation?.document?.emptyFields ?? []
  if (fields.length === 0) return <p className="text-muted-foreground text-xs">{t("wb.noEmptyFields")}</p>
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="w-full max-w-sm"><SelectValue placeholder={t("wb.pickField")} /></SelectTrigger>
      <SelectContent>{fields.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}</SelectContent>
    </Select>
  )
}

function Credential() {
  const { env, credential, set } = useWorkbench()
  const t = useT()
  const [open, setOpen] = useState(false)
  if (credential && !open) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm">{t("wb.signerSummary", { holder: credential.holder, key: `${credential.keyAlgorithm} ${credential.keySize}`, source: credential.source })}</span>
        {credential.isExpired && <Pill tone="danger">{t("signer.card.expired")}</Pill>}
        <Button variant="outline" size="sm" onClick={() => setOpen(true)}>{t("wb.changeSigner")}</Button>
      </div>
    )
  }
  return <CredentialPicker env={env} credential={credential} onCredential={(facts) => { set("credentialId", facts.id); setOpen(false) }} />
}

/** A policy option: the policy in use (the default until a file is uploaded), with a link to view it explained. */
function PolicyField({ kind, uploadId, onChange }: { kind: PolicyKind; uploadId: string | null; onChange: (id: string | null) => void }) {
  const t = useT()
  const [name, setName] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [presets, setPresets] = useState<PolicyPreset[]>([])
  useEffect(() => {
    let current = true
    api.policies.presets().then((all) => { if (current) setPresets(all.filter((p) => p.kind === kind)) }).catch(() => undefined)
    return () => { current = false }
  }, [kind])
  const preset = presets.find((p) => p.id === uploadId)
  useEffect(() => {
    let current = true
    api.policies.view({ kind, uploadId }).then((v) => {
      if (!current) return
      setName(v.name ?? null)
      setError(v.error ?? null)
    }).catch(() => undefined)
    return () => { current = false }
  }, [kind, uploadId])
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Pill tone={error ? "danger" : uploadId ? "info" : "default"}>
          {t("policies.current", { name: name ?? "…" })}{!uploadId && ` (${t("policies.defaultName")})`}
        </Pill>
        {error && <span className="text-destructive">{error}</span>}
      </div>
      {presets.length > 0 && (
        <Select value={preset?.id ?? "__none"} onValueChange={(v) => onChange(v === "__none" ? null : v)}>
          <SelectTrigger className="w-full max-w-sm" aria-label={t("policies.preset")}><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="__none">{t("policies.presetNone")}</SelectItem>
            {presets.map((p) => <SelectItem key={p.id} value={p.id}>{p.title} ({p.name})</SelectItem>)}
          </SelectContent>
        </Select>
      )}
      <div className="flex flex-wrap items-center gap-1">
        <Sheet>
          <SheetTrigger asChild><Button variant="outline" size="sm"><Eye /> {t("policies.view")}</Button></SheetTrigger>
          <SheetContent className="flex w-[min(96vw,1000px)] flex-col p-0 sm:max-w-none">
            <SheetHeader className="sr-only"><SheetTitle>{t(kind === "signing" ? "policies.signing" : "policies.validation")}</SheetTitle><SheetDescription>{t("policies.readOnlyIntro")}</SheetDescription></SheetHeader>
            <PoliciesPage initial={{ kind, uploadId }} readOnly />
          </SheetContent>
        </Sheet>
        <UploadButton label={t("wb.chooseFile")} accept=".json,application/json" onUploaded={(f) => onChange(f.id)} />
        <Button variant="ghost" size="sm" asChild><a href={`/api/policies/${kind}`} download><Download /> {t("wb.downloadDefault")}</a></Button>
        {uploadId && <Button variant="ghost" size="sm" onClick={() => onChange(null)}>{t("wb.clear")}</Button>}
      </div>
    </div>
  )
}
