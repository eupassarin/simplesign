import { useEffect, useRef, useState } from "react"
import { Eye, EyeOff, ImagePlus, Link2, MousePointerClick, PenLine, Plus, RefreshCw, X } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { api } from "@/lib/api"
import type { AppearanceChoice } from "@/lib/types"
import { PdfPreview } from "../PdfPreview"
import { ChoiceCard, Field, Section } from "../ui"
import { useSigning } from "../state"

const fonts = ["Helvetica", "Helvetica-Bold", "Times-Roman", "Times-Bold", "Courier", "Courier-Bold"]

export function FieldStep() {
  const { options, update, state, document } = useSigning()
  const existing = options.fieldMode === "Existing"
  return (
    <div className="space-y-8">
      <Section title="Signature field" description="Where the signature lives in the PDF's form (AcroForm).">
        <div className="grid gap-3 sm:grid-cols-2">
          <ChoiceCard selected={!existing} onSelect={() => update({ fieldMode: "New" })} title="New field" description="Adds a signature field in the new revision." infoId="field.New" icon={<Plus className="size-4" />} state={state("field.New")}>
            <Field label="Field name" description="Unique in the document; no dots.">
              <Input value={options.fieldName} onChange={(e) => update({ fieldName: e.target.value })} />
            </Field>
          </ChoiceCard>
          <ChoiceCard selected={existing} onSelect={() => update({ fieldMode: "Existing", existingFieldName: options.existingFieldName ?? document?.emptyFields[0] ?? null })}
            title="Existing empty field" description="Signs a field the document already has." infoId="field.Existing" icon={<PenLine className="size-4" />} state={state("field.Existing")}>
            <Field label="Field">
              <Select value={options.existingFieldName ?? ""} onValueChange={(existingFieldName) => update({ existingFieldName })}>
                <SelectTrigger className="w-full"><SelectValue placeholder="Choose a field" /></SelectTrigger>
                <SelectContent>{document?.emptyFields.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
          </ChoiceCard>
        </div>
        {state("field.Existing").note && !state("field.Existing").visible && <p className="text-muted-foreground text-xs">{state("field.Existing").note}</p>}
      </Section>

      <Section title="Appearance" infoId="appearance" description="Invisible signatures show only in the viewer's signature panel; a visible stamp is drawn on the page.">
        <div className="grid gap-3 sm:grid-cols-2">
          <ChoiceCard selected={!options.appearance.visible} onSelect={() => update((o) => ({ appearance: { ...o.appearance, visible: false } }))} title="Invisible" icon={<EyeOff className="size-4" />} />
          <ChoiceCard selected={options.appearance.visible} onSelect={() => update((o) => ({ appearance: { ...o.appearance, visible: true } }))} title="Visible stamp" icon={<Eye className="size-4" />} />
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
            {existing ? "Drawn in the existing field's rectangle." : a.autoPosition ? "Auto position: the library picks a free spot." : "Click the page to place the stamp's top-left corner."}
          </span>
          <Button variant="ghost" size="sm" className="h-7" onClick={() => set({ ...a })}>
            <RefreshCw className={rendering ? "animate-spin" : ""} /> Re-render
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
        {previewError && <p className="text-destructive text-xs">Preview: {previewError}</p>}
        {!options.signerName && !a.signerDisplayName && !options.useSignerDetails && (
          <p className="text-muted-foreground rounded-md border border-dashed p-2 text-xs">
            No signer name given: the library prints “Signer”. Set a display name below, or the signer name in Details.
          </p>
        )}
        <p className="text-muted-foreground text-center text-[11px]">The preview is a real signature (B-B) of a throwaway copy, rendered with pdf.js.</p>
      </div>

      <Accordion type="multiple" defaultValue={["placement", "text"]} className="rounded-lg border px-4">
        {!existing && (
          <AccordionItem value="placement">
            <AccordionTrigger>Placement &amp; size</AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="flex items-center justify-between rounded-md border p-3">
                <div><p className="text-sm font-medium">Auto position</p><p className="text-muted-foreground text-xs">SignatureAppearance.Auto(): bottom of the last page, avoiding other stamps.</p></div>
                <Switch checked={a.autoPosition} onCheckedChange={(autoPosition) => set({ autoPosition })} />
              </div>
              {!a.autoPosition && (
                <div className="grid grid-cols-3 gap-3">
                  <Field label="Page"><Input type="number" min={1} value={a.page} onChange={(e) => { set({ page: Number(e.target.value) }); setPage(Number(e.target.value)) }} /></Field>
                  <Field label="X (pt)"><Input type="number" value={a.x} onChange={(e) => set({ x: Number(e.target.value) })} /></Field>
                  <Field label="Y (pt, from bottom)"><Input type="number" value={a.y} onChange={(e) => set({ y: Number(e.target.value) })} /></Field>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <Field label="Width (pt)"><Input type="number" value={a.width ?? ""} onChange={(e) => set({ width: e.target.value ? Number(e.target.value) : null })} placeholder="auto" /></Field>
                <Field label="Height (pt)"><Input type="number" value={a.height ?? ""} onChange={(e) => set({ height: e.target.value ? Number(e.target.value) : null })} placeholder="auto" /></Field>
              </div>
            </AccordionContent>
          </AccordionItem>
        )}
        <AccordionItem value="text">
          <AccordionTrigger>Text</AccordionTrigger>
          <AccordionContent className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Horizontal">
                <Select value={a.textAlignment} onValueChange={(v) => set({ textAlignment: v as AppearanceChoice["textAlignment"] })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{["Left", "Center", "Right"].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field label="Vertical">
                <Select value={a.verticalAlignment} onValueChange={(v) => set({ verticalAlignment: v as AppearanceChoice["verticalAlignment"] })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{["Top", "Middle", "Bottom"].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
            </div>
            <div className="grid grid-cols-3 gap-2 text-sm">
              {([["showDate", "Date"], ["showReason", "Reason"], ["showLocation", "Location"]] as const).map(([key, label]) => (
                <label key={key} className="flex items-center justify-between gap-2 rounded-md border px-3 py-2">{label}<Switch checked={a[key]} onCheckedChange={(v) => set({ [key]: v })} /></label>
              ))}
            </div>
            <label className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm">Shrink text to fit the box<Switch checked={a.shrinkToFit} onCheckedChange={(shrinkToFit) => set({ shrinkToFit })} /></label>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Display name" description="Default: the certificate's holder."><Input value={a.signerDisplayName ?? ""} onChange={(e) => set({ signerDisplayName: e.target.value })} /></Field>
              <Field label="Max text length"><Input type="number" min={10} value={a.maxTextLength} onChange={(e) => set({ maxTextLength: Number(e.target.value) })} /></Field>
              <Field label="“Signed by” label"><Input value={a.signedByLabel ?? ""} placeholder="Signed by" onChange={(e) => set({ signedByLabel: e.target.value || null })} /></Field>
              <Field label="Reason label"><Input value={a.reasonLabel ?? ""} placeholder="Reason: " onChange={(e) => set({ reasonLabel: e.target.value || null })} /></Field>
              <Field label="Location label"><Input value={a.locationLabel ?? ""} placeholder="Location: " onChange={(e) => set({ locationLabel: e.target.value || null })} /></Field>
              <Field label="Date label"><Input value={a.dateLabel ?? ""} placeholder="(none)" onChange={(e) => set({ dateLabel: e.target.value || null })} /></Field>
            </div>
            <ExtraLines lines={a.extraLines} onChange={(extraLines) => set({ extraLines })} />
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="date">
          <AccordionTrigger>Date &amp; time</AccordionTrigger>
          <AccordionContent className="grid grid-cols-3 gap-3">
            <Field label="Format" description="e.g. dd/MM/yyyy HH:mm"><Input value={a.dateFormat ?? ""} onChange={(e) => set({ dateFormat: e.target.value || null })} placeholder="default" /></Field>
            <Field label="Time zone" description="IANA or Windows id"><Input value={a.timeZoneId ?? ""} onChange={(e) => set({ timeZoneId: e.target.value || null })} placeholder="America/Sao_Paulo" /></Field>
            <Field label="Culture"><Input value={a.culture ?? ""} onChange={(e) => set({ culture: e.target.value || null })} placeholder="pt-BR" /></Field>
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="style">
          <AccordionTrigger>Style</AccordionTrigger>
          <AccordionContent className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <ColorField label="Background" value={a.backgroundColor} onChange={(backgroundColor) => set({ backgroundColor })} />
              <ColorField label="Text" value={a.textColor} onChange={(textColor) => set({ textColor })} />
              <ColorField label="Border" value={a.borderColor} onChange={(borderColor) => set({ borderColor })} />
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Field label="Border width"><Input type="number" step={0.5} min={0} value={a.borderWidth} onChange={(e) => set({ borderWidth: Number(e.target.value) })} /></Field>
              <Field label="Font (Base14)">
                <Select value={a.baseFont} onValueChange={(baseFont) => set({ baseFont })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{fonts.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field label="Font size"><Input type="number" value={a.fontSize ?? ""} placeholder="auto" onChange={(e) => set({ fontSize: e.target.value ? Number(e.target.value) : null })} /></Field>
              <Field label="Label size"><Input type="number" value={a.labelFontSize ?? ""} placeholder="auto" onChange={(e) => set({ labelFontSize: e.target.value ? Number(e.target.value) : null })} /></Field>
            </div>
          </AccordionContent>
        </AccordionItem>
        <AccordionItem value="media">
          <AccordionTrigger>QR code &amp; image</AccordionTrigger>
          <AccordionContent className="space-y-4">
            <Field label="Verification URL (QR code)" infoId="appearance.verification" description="For VALIDAR, your HTTPS endpoint built with ValidarItiQrEndpoint.BuildQrCodeUrl.">
              <div className="flex gap-2">
                <Input value={a.verificationUrl ?? ""} onChange={(e) => set({ verificationUrl: e.target.value || null })} placeholder="https://…" />
                <Button variant="outline" size="sm" className="h-9" onClick={() => set({ verificationUrl: "https://example.com/receitas/123?type=prescricao" })}>
                  <Link2 /> VALIDAR-style example
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
  return (
    <Field label="Extra lines" description="Printed after the standard lines (e.g. a protocol number).">
      <div className="space-y-2">
        {lines.map((line, i) => (
          <div key={i} className="flex gap-2">
            <Input value={line} onChange={(e) => onChange(lines.map((l, j) => (j === i ? e.target.value : l)))} />
            <Button variant="ghost" size="icon" onClick={() => onChange(lines.filter((_, j) => j !== i))}><X /></Button>
          </div>
        ))}
        <Button variant="outline" size="sm" onClick={() => onChange([...lines, ""])}><Plus /> Add line</Button>
      </div>
    </Field>
  )
}

function ColorField({ label, value, onChange }: { label: string; value?: string | null; onChange: (v: string | null) => void }) {
  return (
    <Field label={label}>
      <div className="flex items-center gap-2">
        <input type="color" className="h-9 w-10 cursor-pointer rounded-md border bg-transparent p-1" value={value ?? "#ffffff"} onChange={(e) => onChange(e.target.value)} />
        <Input value={value ?? ""} placeholder="none" onChange={(e) => onChange(e.target.value || null)} className="font-mono text-xs" />
      </div>
    </Field>
  )
}

function ImageField({ value, fit, onChange, onFit }: { value?: string | null; fit: AppearanceChoice["imageFit"]; onChange: (id: string | null) => void; onFit: (fit: AppearanceChoice["imageFit"]) => void }) {
  return (
    <div className="grid gap-3 sm:grid-cols-[1fr_160px]">
      <Field label="Background image" description="PNG or JPEG. Transparent PNGs are refused for PDF/A-1.">
        <div className="flex gap-2">
          <Input type="file" accept="image/png,image/jpeg" onChange={async (e) => { const f = e.target.files?.[0]; onChange(f ? (await api.uploadFile(f)).id : null) }} />
          {value && <Button variant="ghost" size="icon" onClick={() => onChange(null)}><X /></Button>}
          {!value && <ImagePlus className="text-muted-foreground mt-2 size-4" />}
        </div>
      </Field>
      <Field label="Fit">
        <Select value={fit} onValueChange={(v) => onFit(v as AppearanceChoice["imageFit"])}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{["Stretch", "Contain", "Cover"].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
    </div>
  )
}
