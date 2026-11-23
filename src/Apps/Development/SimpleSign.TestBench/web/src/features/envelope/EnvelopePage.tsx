import { useEffect, useState } from "react"
import { CheckCircle2, Download, Loader2, PenLine, Plus, ShieldCheck, Trash2, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import type { EnvelopeReport, EnvelopeView } from "@/lib/types"
import { UploadButton } from "../shared/UploadButton"
import { useWorkbench } from "../workbench/state"

/** A signer as the form holds it. */
interface SignerRow {
  name: string
  sandboxSigner: string
  identifierType: string
  identifierValue: string
  role: string
  level: string
  page: number
  rect: string
}

const newRow = (index: number, sandboxSigner = ""): SignerRow => ({
  name: `Signer ${index + 1}`, sandboxSigner, identifierType: "", identifierValue: "", role: "", level: "any", page: 1,
  rect: `72, ${72 + index * 70}, 200, 50`,
})

/**
 * The Envelope task (ADR 0033): a PDF prepared with one signature field per signer and its manifest, then signed field by
 * field with the Sandbox's certificates, in turn; the tab shows where the envelope stands after each step and validates
 * it. Every step writes a new file, which can be downloaded.
 */
export function EnvelopePage() {
  const t = useT()
  const { env } = useWorkbench()
  const sandbox = env?.sandbox
  const usable = sandbox?.signers.filter((s) => s.isUsable) ?? []
  const [document, setDocument] = useState<{ id: string; fileName: string } | null>(null)
  const [rows, setRows] = useState<SignerRow[]>(() => [newRow(0), newRow(1)])
  const [levels, setLevels] = useState<string[]>(["any"])
  const [order, setOrder] = useState<"sequential" | "parallel">("sequential")
  const [certify, setCertify] = useState(false)
  const [tsaUrl, setTsaUrl] = useState(sandbox?.tsaUrl ?? "")
  const [envelope, setEnvelope] = useState<EnvelopeView | null>(null)
  const [report, setReport] = useState<EnvelopeReport | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  useEffect(() => {
    api.envelope.levels().then((l) => setLevels(l.map((x) => x.id))).catch(() => setLevels(["any"]))
  }, [])
  useEffect(() => {
    // The Sandbox's signers, one per row, when it is connected.
    if (usable.length > 0) setRows((current) => current.map((r, i) => (r.sandboxSigner ? r : { ...r, sandboxSigner: usable[i % usable.length].id })))
    if (sandbox?.tsaUrl) setTsaUrl((current) => current || sandbox.tsaUrl)
  }, [sandbox?.url]) // eslint-disable-line react-hooks/exhaustive-deps

  const update = (index: number, change: Partial<SignerRow>) => setRows((current) => current.map((r, i) => (i === index ? { ...r, ...change } : r)))

  async function credentialOf(row: SignerRow) {
    return row.sandboxSigner ? (await api.credentials.sandbox(row.sandboxSigner)).id : null
  }

  async function run<T>(key: string, action: () => Promise<T>) {
    setBusy(key)
    try {
      return await action()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
      return undefined
    } finally {
      setBusy(null)
    }
  }

  const prepare = () => run("prepare", async () => {
    if (!document) return
    const signers = await Promise.all(rows.map(async (r) => {
      const [x, y, width, height] = r.rect.split(",").map((v) => Number(v.trim()))
      return {
        name: r.name, credentialId: await credentialOf(r), identifierType: r.identifierType || null, identifierValue: r.identifierValue || null,
        role: r.role || null, external: false, level: r.level, page: r.page, x, y, width, height,
      }
    }))
    const view = await api.envelope.prepare({ fileId: document.id, order, tsaUrl: tsaUrl || null, certify: certify ? "form-filling" : null, lockDocument: false, signers })
    setEnvelope(view)
    setReport(null)
  })

  const sign = (field: string, index: number) => run(field, async () => {
    if (!envelope) return
    const row = rows[index]
    const credentialId = await credentialOf(row)
    if (!credentialId) {
      toast.error(t("envelope.noSandbox"))
      return
    }
    const level = row.level
    const icpPolicy = level === "icp-ad-rb" ? "ad-rb" : level === "icp-ad-rt" ? "ad-rt" : null
    const needsTimestamp = level === "icp-ad-rt" || level.startsWith("pades-") && level !== "pades-b"
    const view = await api.envelope.sign({
      fileId: envelope.fileId, field, credentialId, icpPolicy, tsaUrl: needsTimestamp ? tsaUrl || null : null,
      certify: certify && index === 0 ? "form-filling" : null,
    })
    setEnvelope(view)
    setReport(null)
  })

  const validate = () => run("validate", async () => {
    if (envelope) setReport(await api.envelope.validate(envelope.fileId))
  })

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 overflow-y-auto p-6">
      <div>
        <h1 className="text-lg font-semibold">{t("envelope.title")}</h1>
        <p className="text-muted-foreground text-sm">{t("envelope.hint")}</p>
      </div>

      <section className="flex flex-col gap-3 rounded-lg border p-4">
        <h2 className="text-sm font-semibold">{t("envelope.document")}</h2>
        <div className="flex items-center gap-3">
          <UploadButton label={t("envelope.upload")} accept="application/pdf,.pdf" onUploaded={(f) => { setDocument(f); setEnvelope(null); setReport(null) }} />
          <span className="text-muted-foreground text-sm">{document?.fileName ?? t("envelope.noDocument")}</span>
        </div>
      </section>

      <section className="flex flex-col gap-3 rounded-lg border p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">{t("envelope.signers")}</h2>
          <Button variant="outline" size="sm" onClick={() => setRows((r) => [...r, newRow(r.length, usable[r.length % Math.max(usable.length, 1)]?.id ?? "")])}><Plus /> {t("envelope.addSigner")}</Button>
        </div>
        {!sandbox && <p className="text-warning text-sm">{t("envelope.noSandbox")}</p>}
        {rows.map((row, i) => (
          <div key={i} className="grid grid-cols-12 items-end gap-2 border-b pb-3 last:border-b-0">
            <Field label={t("envelope.name")} className="col-span-2"><Input value={row.name} onChange={(e) => update(i, { name: e.target.value })} /></Field>
            <Field label={t("envelope.credential")} className="col-span-2">
              <Select value={row.sandboxSigner} onValueChange={(v) => update(i, { sandboxSigner: v })} disabled={usable.length === 0}>
                <SelectTrigger className="w-full"><SelectValue placeholder="—" /></SelectTrigger>
                <SelectContent>{usable.map((s) => <SelectItem key={s.id} value={s.id}>{s.title}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
            <Field label={t("envelope.identifier")} className="col-span-2">
              <div className="flex gap-1">
                <Input className="w-20" placeholder="CPF" value={row.identifierType} onChange={(e) => update(i, { identifierType: e.target.value })} />
                <Input placeholder="…" value={row.identifierValue} onChange={(e) => update(i, { identifierValue: e.target.value })} />
              </div>
            </Field>
            <Field label={t("envelope.role")} className="col-span-1"><Input value={row.role} onChange={(e) => update(i, { role: e.target.value })} /></Field>
            <Field label={t("envelope.level")} className="col-span-2">
              <Select value={row.level} onValueChange={(v) => update(i, { level: v })}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>{levels.map((l) => <SelectItem key={l} value={l}>{l}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
            <Field label={t("envelope.page")} className="col-span-1"><Input type="number" min={1} value={row.page} onChange={(e) => update(i, { page: Number(e.target.value) || 1 })} /></Field>
            <Field label={t("envelope.rect")} className="col-span-1"><Input value={row.rect} onChange={(e) => update(i, { rect: e.target.value })} /></Field>
            <Button variant="ghost" size="icon" className="col-span-1" aria-label={t("envelope.remove")} onClick={() => setRows((r) => r.filter((_, k) => k !== i))} disabled={rows.length === 1}><Trash2 /></Button>
          </div>
        ))}
        <div className="flex flex-wrap items-end gap-4">
          <Field label={t("envelope.order")}>
            <Select value={order} onValueChange={(v) => setOrder(v as "sequential" | "parallel")}>
              <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="sequential">{t("envelope.sequential")}</SelectItem>
                <SelectItem value="parallel">{t("envelope.parallel")}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label={t("envelope.tsa")} className="min-w-80 flex-1"><Input value={tsaUrl} onChange={(e) => setTsaUrl(e.target.value)} placeholder="http://…" /></Field>
          <div className="flex items-center gap-2 pb-2"><Switch id="env-certify" checked={certify} onCheckedChange={setCertify} /><Label htmlFor="env-certify">{t("envelope.certify")}</Label></div>
          <Button onClick={prepare} disabled={!document || busy !== null}>{busy === "prepare" ? <Loader2 className="animate-spin" /> : <PenLine />} {t("envelope.prepare")}</Button>
        </div>
      </section>

      {envelope && (
        <section className="flex flex-col gap-3 rounded-lg border p-4">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-sm font-semibold">{t("envelope.status")}</h2>
            <Badge variant={envelope.status === "Inconsistent" ? "destructive" : "secondary"}>{envelope.status}</Badge>
            {envelope.next && <span className="text-muted-foreground text-sm">{t("envelope.next")}: <b>{envelope.next}</b></span>}
            <div className="ml-auto flex gap-2">
              <Button variant="outline" size="sm" asChild><a href={api.fileUrl(envelope.fileId, true)}><Download /> {envelope.fileName}</a></Button>
              <Button size="sm" onClick={validate} disabled={busy !== null || !envelope.fields.some((f) => f.isSigned)}>{busy === "validate" ? <Loader2 className="animate-spin" /> : <ShieldCheck />} {t("envelope.validate")}</Button>
            </div>
          </div>
          <Table>
            <TableHeader>
              <TableRow><TableHead>{t("envelope.field")}</TableHead><TableHead>{t("envelope.signer")}</TableHead><TableHead>{t("envelope.level")}</TableHead><TableHead>{t("envelope.page")}</TableHead><TableHead>{t("envelope.signed")}</TableHead><TableHead /></TableRow>
            </TableHeader>
            <TableBody>
              {envelope.fields.map((f, i) => (
                <TableRow key={f.name}>
                  <TableCell className="font-mono text-xs">{f.name}</TableCell>
                  <TableCell>{f.signer}{f.role ? <span className="text-muted-foreground"> · {f.role}</span> : null}</TableCell>
                  <TableCell className="font-mono text-xs">{f.level}</TableCell>
                  <TableCell>{f.page}</TableCell>
                  <TableCell>{f.isSigned ? <span className="flex items-center gap-1"><CheckCircle2 className="text-success size-4" /> {f.signedBy}</span> : "—"}</TableCell>
                  <TableCell className="text-right">
                    {!f.isSigned && <Button size="sm" variant="outline" onClick={() => sign(f.name, i)} disabled={busy !== null}>{busy === f.name ? <Loader2 className="animate-spin" /> : <PenLine />} {t("envelope.sign")}</Button>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {envelope.problems.length > 0 && (
            <div className="text-destructive text-sm">{t("envelope.problems")}: {envelope.problems.join(" ")}</div>
          )}
          {envelope.manifest && (
            <details>
              <summary className="cursor-pointer text-sm font-medium">{t("envelope.manifest")}</summary>
              <pre className="bg-muted mt-2 max-h-80 overflow-auto rounded p-3 text-xs">{envelope.manifest}</pre>
            </details>
          )}
        </section>
      )}

      {report && (
        <section className="flex flex-col gap-3 rounded-lg border p-4">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold">{t("envelope.report")}</h2>
            {report.isComplete ? <CheckCircle2 className="text-success size-4" /> : <XCircle className="text-destructive size-4" />}
          </div>
          <pre className="bg-muted max-h-[28rem] overflow-auto rounded p-3 text-xs">{JSON.stringify(report, null, 2)}</pre>
        </section>
      )}
    </div>
  )
}

function Field({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
  return (
    <div className={className}>
      <Label className="mb-1 block text-xs">{label}</Label>
      {children}
    </div>
  )
}
