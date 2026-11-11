import { useState } from "react"
import { Download, ExternalLink, FlaskConical, Loader2, Plug, RefreshCw, Unplug } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { SheetClose } from "@/components/ui/sheet"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import { KeyValue, Pill, Section } from "../shared/ui"
import { useWorkbench } from "../workbench/state"

/**
 * The link to a SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox): a separate app with a test PKI
 * and its services (CRLs over HTTP, HTTPS and LDAP, OCSP, TSAs, CSC) and the failures to switch on.
 * Connected, its root is trusted, its services are reachable and its signers can be chosen.
 */
export function SandboxPage() {
  const { env, setEnv, signWithSandbox } = useWorkbench()
  const t = useT()
  const sandbox = env?.sandbox ?? null
  const [url, setUrl] = useState(sandbox?.url ?? env?.rememberedSandboxUrl ?? "http://localhost:5300/")
  const [busy, setBusy] = useState(false)
  const run = async (action: () => Promise<typeof env>, done?: string) => {
    setBusy(true)
    try {
      const next = await action()
      if (next) setEnv(next)
      if (done) toast.success(done)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="space-y-8 p-6 lg:p-8">
        <header className="space-y-1">
          <h2 className="flex items-center gap-2 text-2xl font-semibold tracking-tight"><FlaskConical className="size-6" /> {t("sandbox.title")}</h2>
          <p className="text-muted-foreground max-w-3xl text-sm">{t("sandbox.intro")}</p>
        </header>

        <Section title={t("sandbox.connection")} description={t("sandbox.connectionHint")}>
          <div className="flex max-w-2xl flex-wrap items-center gap-2">
            <Input value={url} onChange={(e) => setUrl(e.target.value)} className="min-w-64 flex-1 font-mono" aria-label={t("sandbox.url")} />
            {sandbox ? (
              <Button variant="outline" disabled={busy} onClick={() => run(api.sandbox.disconnect, t("sandbox.disconnected"))}><Unplug /> {t("sandbox.disconnect")}</Button>
            ) : (
              <Button disabled={busy} onClick={() => run(() => api.sandbox.connect(url), t("sandbox.connected"))}>
                {busy ? <Loader2 className="animate-spin" /> : <Plug />} {t("sandbox.connect")}
              </Button>
            )}
          </div>
          {!sandbox && env?.sandboxError && <p className="text-destructive text-sm">{env.sandboxError}</p>}
          {!sandbox && (
            <div className="bg-muted/40 max-w-2xl space-y-1 rounded-lg border p-3 text-sm">
              <p>{t("sandbox.start")}</p>
              <code className="block font-mono text-xs">dotnet run --project src/Apps/SimpleSign.Sandbox</code>
            </div>
          )}
        </Section>

        {sandbox && (
          <>
            <Section title={sandbox.name} description={t("sandbox.connectedHint")}
              aside={
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" asChild><a href={sandbox.url} target="_blank" rel="noreferrer"><ExternalLink /> {t("sandbox.open")}</a></Button>
                  <Button variant="outline" size="sm" disabled={busy} onClick={() => run(api.sandbox.samples, t("sandbox.samplesDone"))}><RefreshCw /> {t("sandbox.samples")}</Button>
                </div>
              }>
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="rounded-lg border px-4 py-2">
                  <KeyValue stacked mono label="URL" copy={sandbox.url}>{sandbox.url}</KeyValue>
                  <KeyValue stacked label={t("sandbox.root")}>{sandbox.rootSubject}</KeyValue>
                  <KeyValue stacked mono label={t("sandbox.thumbprint")}>{sandbox.rootThumbprint}</KeyValue>
                  <KeyValue stacked mono label={t("sandbox.origins")}>{sandbox.loopbackOrigins.join(", ")}</KeyValue>
                </div>
                <div className="rounded-lg border px-4 py-2">
                  <KeyValue stacked mono label={t("sandbox.tsa")} copy={sandbox.tsaUrl}>{sandbox.tsaUrl}</KeyValue>
                  <KeyValue stacked mono label={t("sandbox.tsaRevoked")} copy={sandbox.revokedTsaUrl}>{sandbox.revokedTsaUrl}</KeyValue>
                  <KeyValue stacked mono label={t("sandbox.tsaWrongName")} copy={sandbox.wrongNameTsaUrl}>{sandbox.wrongNameTsaUrl}</KeyValue>
                  <KeyValue stacked mono label="CSC v2" copy={sandbox.cscUrl}>{sandbox.cscUrl}</KeyValue>
                </div>
              </div>
              <AdobeTrust />
            </Section>

            <Section title={t("sandbox.signers")} description={t("sandbox.signersHint")}>
              <ul className="divide-y rounded-lg border">
                {sandbox.signers.map((s) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
                    <span className="font-medium">{s.title}</span>
                    <span className="text-muted-foreground font-mono text-[11px]">{s.id}</span>
                    {s.problem ? <Pill tone="warning">{s.problem}</Pill> : <Pill tone="success">{t("sandbox.usable")}</Pill>}
                    {/* Inside the panel's sheet: picking a signer closes it, back to the workbench. */}
                    <SheetClose asChild>
                      <Button variant="ghost" size="sm" className="ml-auto" onClick={() => void signWithSandbox(s.id)}>{t("sandbox.signWith")}</Button>
                    </SheetClose>
                  </li>
                ))}
              </ul>
            </Section>
          </>
        )}
      </div>
    </div>
  )
}

/**
 * Adobe Acrobat/Reader trusts only its own list (AATL) and what is imported: a signature from the Sandbox's PKI shows
 * "Signer's identity is unknown" until its root is imported as a trusted root. The root as a .cer, and how.
 */
function AdobeTrust() {
  const t = useT()
  return (
    <div className="mt-4 space-y-2 rounded-lg border px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium">{t("sandbox.adobe.title")}</p>
          <p className="text-muted-foreground text-xs leading-relaxed">{t("sandbox.adobe.about")}</p>
        </div>
        <Button variant="outline" size="sm" asChild><a href="/api/sandbox/root.cer" download><Download /> {t("sandbox.adobe.download")}</a></Button>
      </div>
      <ol className="text-muted-foreground list-decimal space-y-0.5 pl-5 text-xs leading-relaxed">
        <li>{t("sandbox.adobe.step1")}</li>
        <li>{t("sandbox.adobe.step2")}</li>
        <li>{t("sandbox.adobe.step3")}</li>
        <li>{t("sandbox.adobe.step4")}</li>
      </ol>
      <p className="text-muted-foreground text-xs leading-relaxed">{t("sandbox.adobe.time")}</p>
    </div>
  )
}
