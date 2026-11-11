import { useCallback, useEffect, useState } from "react"
import { Download, FlaskConical, Loader2, Plug, RefreshCw, TriangleAlert, Unplug } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import type { EnvironmentInfo } from "@/lib/types"
import { cn } from "@/lib/utils"
import { KeyValue, Pill, Section } from "../shared/ui"
import { useWorkbench } from "../workbench/state"
import { api as admin } from "./api"
import { EnvironmentTab } from "./EnvironmentTab"
import { FaultsTab } from "./FaultsTab"
import { useI18n as useSandboxI18n } from "./i18n"
import { LogTab } from "./LogTab"
import { PkiTab } from "./PkiTab"
import { load, save } from "./storage"
import type { PkiView, SandboxFaults, SandboxInfo } from "./types"

const tabs = ["overview", "environment", "pki", "faults", "log"] as const
type Tab = (typeof tabs)[number]

const faultsOn = (f: SandboxFaults | null) =>
  !!f && (f.tsa !== "None" || f.crl !== "None" || f.ocsp !== "None" || (f.trustedList ?? "None") !== "None")

/**
 * The one place of the SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox), a separate app with a test PKI and its
 * services on real endpoints. Not connected, the button opens a popup to connect and how to start one. Connected,
 * it opens everything: the connection and its signers, the environment's addresses, the PKI (revocations,
 * downloads), the failures and the request log, all through the Sandbox's own admin API (passed through by the
 * TestBench, nothing kept here: another client switching a failure shows here too).
 */
export function SandboxControl() {
  const { env } = useWorkbench()
  const t = useT()
  const sandbox = env?.sandbox ?? null
  const [open, setOpen] = useState(false)
  const [faults, setFaults] = useState<SandboxFaults | null>(null)
  // The failures can be switched by any client of the Sandbox (a playbook, curl): read them now and then.
  useEffect(() => {
    if (!sandbox) {
      setFaults(null)
      return
    }
    let stopped = false
    const read = () => admin.faults().then((f) => { if (!stopped) setFaults(f) }).catch(() => {})
    void read()
    const timer = setInterval(read, 10000)
    return () => { stopped = true; clearInterval(timer) }
  }, [sandbox?.url])
  const failing = faultsOn(faults)
  const label = sandbox ? `Sandbox: ${sandbox.name}` : t("sandbox.button")
  const trigger = (
    <Button variant="ghost" size="sm" aria-label={label} className={cn("h-8", sandbox && "border-info/60 bg-info/10 border", failing && "border-destructive/60 bg-destructive/10")}
      onClick={sandbox ? () => setOpen(true) : undefined}>
      {failing ? <TriangleAlert className="text-destructive" /> : <FlaskConical />}<span className="max-xl:hidden">{label}</span>
    </Button>
  )
  const hint = failing ? t("sandbox.faultsOn") : t("app.sandboxHint")
  if (!sandbox) {
    return (
      <Popover>
        <Tooltip>
          <TooltipTrigger asChild><PopoverTrigger asChild>{trigger}</PopoverTrigger></TooltipTrigger>
          <TooltipContent className="max-w-64">{hint}</TooltipContent>
        </Tooltip>
        <PopoverContent align="start" className="w-96 text-sm"><ConnectForm /></PopoverContent>
      </Popover>
    )
  }
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>{trigger}</TooltipTrigger>
        <TooltipContent className="max-w-64">{hint}</TooltipContent>
      </Tooltip>
      <SheetContent className="flex w-[min(96vw,1200px)] flex-col p-0 sm:max-w-none">
        <SheetHeader className="sr-only"><SheetTitle>{label}</SheetTitle><SheetDescription>{t("app.sandboxHint")}</SheetDescription></SheetHeader>
        <SandboxWorkspace faults={faults} onFaults={setFaults} onClose={() => setOpen(false)} />
      </SheetContent>
    </Sheet>
  )
}

/** Not connected: the address (the one connected last), Connect, and how to start a Sandbox. */
function ConnectForm() {
  const { env, setEnv } = useWorkbench()
  const t = useT()
  const [url, setUrl] = useState(env?.rememberedSandboxUrl ?? "http://localhost:5300/")
  const [busy, setBusy] = useState(false)
  const connect = async () => {
    setBusy(true)
    try {
      setEnv(await api.sandbox.connect(url))
      toast.success(t("sandbox.connected"))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-3">
      <div>
        <p className="flex items-center gap-1.5 font-medium"><FlaskConical className="size-4" /> {t("sandbox.title")}</p>
        <p className="text-muted-foreground text-xs leading-relaxed">{t("sandbox.about")}</p>
      </div>
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); void connect() }}>
        <Input value={url} onChange={(e) => setUrl(e.target.value)} className="font-mono text-xs" aria-label={t("sandbox.url")} />
        <Button type="submit" size="sm" className="h-9" disabled={busy}>{busy ? <Loader2 className="animate-spin" /> : <Plug />} {t("sandbox.connect")}</Button>
      </form>
      {env?.sandboxError && <p className="text-destructive text-xs leading-relaxed break-words">{env.sandboxError}</p>}
      <div className="space-y-1.5">
        <p className="text-muted-foreground text-xs">{t("sandbox.start")}</p>
        <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">dotnet run --project src/Apps/SimpleSign.Sandbox</pre>
        <p className="text-muted-foreground text-xs">{t("sandbox.docker")}</p>
        <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">{"docker build -f src/Apps/SimpleSign.Sandbox/Dockerfile -t simplesign-sandbox .\ndocker run --rm -p 127.0.0.1:5300-5302:5300-5302 simplesign-sandbox"}</pre>
      </div>
    </div>
  )
}

/** Connected: the header (name, failures, samples, disconnect) and the tabs. */
function SandboxWorkspace({ faults, onFaults, onClose }: { faults: SandboxFaults | null; onFaults: (f: SandboxFaults) => void; onClose: () => void }) {
  const { env, setEnv } = useWorkbench()
  const t = useT()
  const s = useSandboxI18n().t
  const sandbox = env?.sandbox
  const [info, setInfo] = useState<SandboxInfo | null>(null)
  const [pki, setPki] = useState<PkiView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [tab, setTabState] = useState<Tab>(() => tabs.find((x) => x === load("tab")) ?? "overview")
  const setTab = (next: string) => {
    const known = tabs.find((x) => x === next)
    if (!known) return
    setTabState(known)
    save("tab", known)
  }
  const refresh = useCallback(() => {
    Promise.all([admin.info(), admin.pki()])
      .then(([i, p]) => { setInfo(i); setPki(p); setError(null) })
      .catch((e: Error) => setError(e.message))
  }, [])
  useEffect(refresh, [refresh])
  const run = async (action: () => Promise<EnvironmentInfo>, done: string) => {
    setBusy(true)
    try {
      setEnv(await action())
      toast.success(done)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  if (!sandbox) return null
  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="space-y-6 p-6 lg:p-8">
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <h2 className="flex flex-wrap items-center gap-2 text-2xl font-semibold tracking-tight">
              <FlaskConical className="size-6" /> {t("sandbox.title")} <Pill tone="info">{sandbox.name}</Pill>
              {faultsOn(faults) && <button type="button" onClick={() => setTab("faults")}><Pill tone="danger"><TriangleAlert className="size-3" /> {t("sandbox.faultsOn")}</Pill></button>}
            </h2>
            <p className="text-muted-foreground font-mono text-xs">{info ? s("app.certificatesPointTo", { url: info.baseUrl }) : sandbox.url}</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={busy} onClick={() => run(api.sandbox.samples, t("sandbox.samplesDone"))}><RefreshCw /> {t("sandbox.samples")}</Button>
            <Button variant="outline" size="sm" disabled={busy} onClick={() => { onClose(); void run(api.sandbox.disconnect, t("sandbox.disconnected")) }}><Unplug /> {t("sandbox.disconnect")}</Button>
          </div>
        </header>
        {error && <p className="text-destructive text-sm">{s("common.error")}: {error}</p>}
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="overview">{t("sandbox.overview")}</TabsTrigger>
            <TabsTrigger value="environment">{s("tabs.environment")}</TabsTrigger>
            <TabsTrigger value="pki">{s("tabs.pki")}</TabsTrigger>
            <TabsTrigger value="faults">{s("tabs.faults")}</TabsTrigger>
            <TabsTrigger value="log">{s("tabs.log")}</TabsTrigger>
          </TabsList>
          <div className="pt-4">
            <TabsContent value="overview"><Overview pki={pki} onClose={onClose} /></TabsContent>
            <TabsContent value="environment">{info ? <EnvironmentTab info={info} /> : <Loader2 className="text-muted-foreground size-5 animate-spin" />}</TabsContent>
            <TabsContent value="pki">{info && pki ? <PkiTab info={info} pki={pki} onChanged={refresh} /> : <Loader2 className="text-muted-foreground size-5 animate-spin" />}</TabsContent>
            <TabsContent value="faults"><FaultsTab initial={faults} onChanged={onFaults} /></TabsContent>
            <TabsContent value="log"><LogTab /></TabsContent>
          </div>
        </Tabs>
      </div>
    </div>
  )
}

/** What the TestBench uses of the Sandbox: its root and services, its signers (revoked ones marked), and its root for Adobe. */
function Overview({ pki, onClose }: { pki: PkiView | null; onClose: () => void }) {
  const { env, signWithSandbox } = useWorkbench()
  const t = useT()
  const sandbox = env?.sandbox
  if (!sandbox) return null
  const revoked = new Set(pki?.certificates.filter((c) => c.revokedAt).map((c) => c.id) ?? [])
  return (
    <div className="space-y-8">
      <Section title={sandbox.name} description={t("sandbox.connectedHint")}>
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
          {sandbox.signers.map((x) => (
            <li key={x.id} className="flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
              <span className="font-medium">{x.title}</span>
              <span className="text-muted-foreground font-mono text-[11px]">{x.id}</span>
              {revoked.has(x.id) && <Pill tone="danger">{t("sandbox.revoked")}</Pill>}
              {x.problem ? <Pill tone="warning">{x.problem}</Pill> : !revoked.has(x.id) && <Pill tone="success">{t("sandbox.usable")}</Pill>}
              {/* Picking a signer closes the panel, back to the workbench. */}
              <Button variant="ghost" size="sm" className="ml-auto" onClick={() => { onClose(); void signWithSandbox(x.id) }}>{t("sandbox.signWith")}</Button>
            </li>
          ))}
        </ul>
      </Section>
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
