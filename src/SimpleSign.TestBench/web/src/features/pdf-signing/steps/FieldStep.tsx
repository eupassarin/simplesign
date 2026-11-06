import { useEffect, useRef, useState } from "react"
import { Eye, EyeOff, ImagePlus, Link2, MousePointerClick, PenLine, Plus, RefreshCw, X } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { AppearanceChoice } from "@/lib/types"
import { PdfPreview } from "../PdfPreview"
import { ChoiceCard, Field, Section } from "../ui"
import { useSigning } from "../state"

const fonts = ["Helvetica", "Helvetica-Bold", "Times-Roman", "Times-Bold", "Courier", "Courier-Bold"]

export function FieldStep() {
  const { options, update, state, document } = useSigning()
  const existing = options.fieldMode === "Existing"
  const t = useT()
  return (
    <div className="space-y-8">
      <Section title={t("field.title")} description={t("field.hint")}>
        <div className="grid gap-3 sm:grid-cols-2">
          <ChoiceCard selected={!existing} onSelect={() => update({ fieldMode: "New" })} title={t("field.new")} description={t("field.newHint")} infoId="field.New" icon={<Plus className="size-4" />} state={state("field.New")}>
            <Field label={t("field.name")} description={t("field.nameHint")}>
              <Input value={options.fieldName} onChange={(e) => update({ fieldName: e.target.value })} />
            </Field>
          </ChoiceCard>
          <ChoiceCard selected={existing} onSelect={() => update({ fieldMode: "Existing", existingFieldName: options.existingFieldName ?? document?.emptyFields[0] ?? null })}
            title={t("field.existing")} description={t("field.existingHint")} infoId="field.Existing" icon={<PenLine className="size-4" />} state={state("field.Existing")}>
            <Field label={t("field.field")}>
              <Select value={options.existingFieldName ?? ""} onValueChange={(existingFieldName) => update({ existingFieldName })}>
                <SelectTrigger className="w-full"><SelectValue placeholder={t("field.choose")} /></SelectTrigger>
                <SelectContent>{document?.emptyFields.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
          </ChoiceCard>
        </div>
        {state("field.Existing").note && !state("field.Existing").visible && <p className="text-muted-foreground text-xs">{state("field.Existing").note}</p>}
      </Section>

      <Section title={t("field.appearance")} infoId="appearance" description={t("field.appearanceHint")}>
        <div className="grid gap-3 sm:grid-cols-2">
          <ChoiceCard selected={!options.appearance.visible} onSelect={() => update((o) => ({ appearance: { ...o.appearance, visible: false } }))} title={t("field.invisible")} icon={<EyeOff className="size-4" />} />
          <ChoiceCard selected={options.appearance.visible} onSelect={() => update((o) => ({ appearance: { ...o.appearance, visible: true } }))} title={t("field.visible")} icon={<Eye className="size-4" />} />
        </div>
      </Section>

      {options.appearance.visible && <AppearanceEditor existing={existing} />}
    </div>
  )
}

function AppearanceEditor({ existing }: { existing: boolean }) {
  const { options, update } = useSigning()
  const a = options.appearance
  const set = (patch: Partial<AppearanceChoice>) => update((o) => ({ appearance: { ...o.appearance, ...patch } }))
  const [previewId, setPreviewId] = useState<string | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [rendering, setRendering] = useState(false)
  const [page, setPage] = useState(a.page)
  const sequence = useRef(0)
  const t = useT()

  // The preview signs a throwaway copy (B-B, sandbox key) with exactly these appearance options.
  useEffect(() => {
    if (!options.documentId) return
    const id = ++sequence.current
    setRendering(true)
    const timer = setTimeout(() => {
      api
        .preview(options)
        .then((r) => id === sequence.current && (setPreviewId(r.fileId), setPreviewError(null)))
        .catch((e: Error) => id === sequence.current && setPreviewError(e.message))
        .finally(() => id === sequence.current && setRendering(false))
    }, 450)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [options.documentId, options.credentialId, options.fieldMode, options.existingFieldName, options.fieldName, options.appearance, options.reason, options.location, options.signerName, options.signingTime])

  const url = previewId ? api.fileUrl(previewId) : options.documentId ? api.fileUrl(options.documentId) : null
  return (
    <div className="@container">
    <div className="grid gap-6 @5xl:grid-cols-[minmax(0,560px)_minmax(0,1fr)]">
      <div className="space-y-2 @5xl:sticky @5xl:top-4 @5xl:self-start">
        <div className="text-muted-foreground flex items-center justify-between text-xs">
          <span className="flex items-center gap-1.5">
            <MousePointerClick className="size-3.5" />
            {t(existing ? "field.preview.existing" : a.autoPosition ? "field.preview.auto" : "field.preview.click")}
          </span>
          <Button variant="ghost" size="sm" className="h-7" onClick={() => set({ ...a })}>
            <RefreshCw className={rendering ? "animate-spin" : ""} /> {t("field.preview.rerender")}
          </Button>
        </div>
        {url && (
          <PdfPreview
            url={url}
            page={page}
            onPageChange={(p) => {
              setPage(p)
              if (!existing && !a.autoPosition) set({ page: p })
            }}
            rendering={rendering}
            box={!existing && !a.autoPosition && page === a.page && !previewId ? { x: a.x, y: a.y, width: a.width ?? 200, height: a.height ?? 60 } : null}
            onPlace={existing || a.autoPosition ? undefined : (x, y) => set({ page, x, y: Math.max(0, y - (a.height ?? 60)) })}
          />
        )}
        {previewError && <p className="text-destructive text-xs">{t("field.preview.error", { error: previewError })}</p>}
        {!options.signerName && !a.signerDisplayName && !options.useSignerDetails && (
          <p className="text-muted-foreground rounded-md border border-dashed p-2 text-xs">
            {t("field.preview.noName")}
          </p>
        )}
        <p className="text-muted-foreground text-center text-[11px]">{t("field.preview.note")}</p>
      </div>

      <Accordion type="multiple" defaultValue={["placement", "text"]} className="rounded-lg border px-4">
        {!existing && (
          <AccordionItem value="placement">
            <AccordionTrigger>{t("field.placement")}</AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="flex items-center justify-between rounded-md border p-3">
                <div><p className="text-sm font-medium">{t("field.auto")}</p><p className="text-muted-foreground text-xs">{t("field.autoHint")}</p></div>
                <Switch checked={a.autoPosition} onCheckedChange={(autoPosition) => set({ autoPosition })} />
              </div>
              {!a.autoPosition && (
                <div className="grid grid-cols-3 gap-3">
                  <Field label={t("field.page")}><Input type="number" min={1} value={a.page} onChange={(e) => { set({ page: Number(e.target.value) }); setPage(Number(e.target.value)) }} /></Field>
                  <Field label="X (pt)"><Input type="number" value={a.x} onChange={(e) => set({ x: Number(e.target.value) })} /></Field>
                  <Field label={t("field.y")}><Input type="number" value={a.y} onChange={(e) => set({ y: Number(e.target.value) })} /></Field>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <Field label={t("field.width")}><Input type="number" value={a.width ?? ""} onChange={(e) => set({ width: e.target.value ? Number(e.target.value) : null })} placeholder="auto" /></Field>
                <Field label={t("field.height")}><Input type="number" value={a.height ?? ""} onChange={(e) => set({ height: e.target.value ? Number(e.target.value) : null })} placeholder="auto" /></Field>
              </div>
            </AccordionContent>
          </AccordionItem>
        )}
        <AccordionItem value="text">
          <AccordionTrigger>{t("field.text")}</AccordionTrigger>
          <AccordionContent className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Field label={t("field.horizontal")}>
                <Select value={a.textAlignment} onValueChange={(v) => set({ textAlignment: v as AppearanceChoice["textAlignment"] })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{["Left", "Center", "Right"].map((v) => <SelectItem key={v} value={v}>{t(`field.align.${v}` as MessageKey)}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field label={t("field.vertical")}>
                <Select value={a.verticalAlignment} onValueChange={(v) => set({ verticalAlignment: v as AppearanceChoice["verticalAlignment"] })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{["Top", "Middle", "Bottom"].map((v) => <SelectItem key={v} value={v}>{t(`field.align.${v}` as MessageKey)}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
            </div>
            <div className="grid grid-cols-3 gap-2 text-sm">
              {([["showDate", "field.showDate"], ["showReason", "field.showReason"], ["showLocation", "field.showLocation"]] as const).map(([key, label]) => (
                <label key={key} className="flex items-center justify-between gap-2 rounded-md border px-3 py-2">{t(label)}<Switch checked={a[key]} onCheckedChange={(v) => set({ [key]: v })} /></label>
              ))}
            </div>
            <label className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm">{t("field.shrink")}<Switch checked={a.shrinkToFit} onCheckedChange={(shrinkToFit) => set({ shrinkToFit })} /></label>
            <div className="grid grid-cols-2 gap-3">
              <Field label={t("field.displayName")} description={t("field.displayNameHint")}><Input value={a.signerDisplayName ?? ""} onChange={(e) => set({ signerDisplayName: e.target.value })} /></Field>
              <Field label={t("field.maxText")}><Input type="number" min={10} value={a.maxTextLength} onChange={(e) => set({ maxTextLength: Number(e.target.value) })} /></Field>
              <Field label={t("field.signedByLabel")}><Input value={a.signedByLabel ?? ""} placeholder="Signed by" onChange={(e) => set({ signedByLabel: e.target.value || null })} /></Field>
              <Field label={t("field.reasonLabel")}><Input value={a.reasonLabel ?? ""} placeholder="Reason: " onChange={(e) => set({ reasonLabel: e.target.value || null })} /></Field>
              <Field label={t("field.locationLabel")}><Input value={a.locationLabel ?? ""} placeholder="Location: " onChange={(e) => set({ locationLabel: e.target.value || null })} /></Field>
              <Field label={t("field.dateLabel")}><Input value={a.dateLabel ?? ""} placeholder={t("field.none")} onChange={(e) => set({ dateLabel: e.target.value || null })} /></Field>
            </div>
            <ExtraLines lines={a.extraLines} onChange={(extraLines) => set({ extraLines })} />
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="date">
          <AccordionTrigger>{t("field.date")}</AccordionTrigger>
          <AccordionContent className="grid grid-cols-3 gap-3">
            <Field label={t("field.format")} description={t("field.formatHint")}><Input value={a.dateFormat ?? ""} onChange={(e) => set({ dateFormat: e.target.value || null })} placeholder={t("field.default")} /></Field>
            <Field label={t("field.timeZone")} description={t("field.timeZoneHint")}><Input value={a.timeZoneId ?? ""} onChange={(e) => set({ timeZoneId: e.target.value || null })} placeholder="America/Sao_Paulo" /></Field>
            <Field label={t("field.culture")}><Input value={a.culture ?? ""} onChange={(e) => set({ culture: e.target.value || null })} placeholder="pt-BR" /></Field>
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="style">
          <AccordionTrigger>{t("field.style")}</AccordionTrigger>
          <AccordionContent className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <ColorField label={t("field.background")} value={a.backgroundColor} onChange={(backgroundColor) => set({ backgroundColor })} />
              <ColorField label={t("field.textColor")} value={a.textColor} onChange={(textColor) => set({ textColor })} />
              <ColorField label={t("field.border")} value={a.borderColor} onChange={(borderColor) => set({ borderColor })} />
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Field label={t("field.borderWidth")}><Input type="number" step={0.5} min={0} value={a.borderWidth} onChange={(e) => set({ borderWidth: Number(e.target.value) })} /></Field>
              <Field label={t("field.font")}>
                <Select value={a.baseFont} onValueChange={(baseFont) => set({ baseFont })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{fonts.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field label={t("field.fontSize")}><Input type="number" value={a.fontSize ?? ""} placeholder={t("field.autoValue")} onChange={(e) => set({ fontSize: e.target.value ? Number(e.target.value) : null })} /></Field>
              <Field label={t("field.labelSize")}><Input type="number" value={a.labelFontSize ?? ""} placeholder={t("field.autoValue")} onChange={(e) => set({ labelFontSize: e.target.value ? Number(e.target.value) : null })} /></Field>
            </div>
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="media">
          <AccordionTrigger>{t("field.media")}</AccordionTrigger>
          <AccordionContent className="space-y-4">
            <Field label={t("field.qr")} infoId="appearance.verification" description={t("field.qrHint")}>
              <div className="flex gap-2">
                <Input value={a.verificationUrl ?? ""} onChange={(e) => set({ verificationUrl: e.target.value || null })} placeholder="https://…" />
                <Button variant="outline" size="sm" className="h-9" onClick={() => set({ verificationUrl: "https://example.com/receitas/123?type=prescricao" })}>
                  <Link2 /> {t("field.qrExample")}
                </Button>
              </div>
            </Field>
            <ImageField value={a.imageUploadId} fit={a.imageFit} onChange={(imageUploadId) => set({ imageUploadId })} onFit={(imageFit) => set({ imageFit })} />
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
    </div>
  )
}

function ExtraLines({ lines, onChange }: { lines: string[]; onChange: (lines: string[]) => void }) {
  const t = useT()
  return (
    <Field label={t("field.extraLines")} description={t("field.extraLinesHint")}>
      <div className="space-y-2">
        {lines.map((line, i) => (
          <div key={i} className="flex gap-2">
            <Input value={line} onChange={(e) => onChange(lines.map((l, j) => (j === i ? e.target.value : l)))} />
            <Button variant="ghost" size="icon" onClick={() => onChange(lines.filter((_, j) => j !== i))}><X /></Button>
          </div>
        ))}
        <Button variant="outline" size="sm" onClick={() => onChange([...lines, ""])}><Plus /> {t("field.addLine")}</Button>
      </div>
    </Field>
  )
}

function ColorField({ label, value, onChange }: { label: string; value?: string | null; onChange: (v: string | null) => void }) {
  const t = useT()
  return (
    <Field label={label}>
      <div className="flex items-center gap-2">
        <input type="color" className="h-9 w-10 cursor-pointer rounded-md border bg-transparent p-1" value={value ?? "#ffffff"} onChange={(e) => onChange(e.target.value)} />
        <Input value={value ?? ""} placeholder={t("field.none")} onChange={(e) => onChange(e.target.value || null)} className="font-mono text-xs" />
      </div>
    </Field>
  )
}

function ImageField({ value, fit, onChange, onFit }: { value?: string | null; fit: AppearanceChoice["imageFit"]; onChange: (id: string | null) => void; onFit: (fit: AppearanceChoice["imageFit"]) => void }) {
  const t = useT()
  return (
    <div className="grid gap-3 sm:grid-cols-[1fr_160px]">
      <Field label={t("field.image")} description={t("field.imageHint")}>
        <div className="flex gap-2">
          <Input type="file" accept="image/png,image/jpeg" onChange={async (e) => { const f = e.target.files?.[0]; onChange(f ? (await api.uploadFile(f)).id : null) }} />
          {value && <Button variant="ghost" size="icon" onClick={() => onChange(null)}><X /></Button>}
          {!value && <ImagePlus className="text-muted-foreground mt-2 size-4" />}
        </div>
      </Field>
      <Field label={t("field.fit")}>
        <Select value={fit} onValueChange={(v) => onFit(v as AppearanceChoice["imageFit"])}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{["Stretch", "Contain", "Cover"].map((v) => <SelectItem key={v} value={v}>{t(`field.fits.${v}` as MessageKey)}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
    </div>
  )
}
