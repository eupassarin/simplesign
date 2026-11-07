import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { Cloud, FileKey2, KeyRound, Loader2, MonitorSmartphone, RefreshCw, ShieldCheck, Usb } from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { CredentialFacts, CscCredentialSummary, EnvironmentInfo, EnvironmentMode, Pkcs11Driver, StoreCertificate } from "@/lib/types"
import { ChoiceCard, Explain, Field, KeyValue, Pill, Section } from "../shared/ui"

interface PickerContext {
  environment: EnvironmentMode
  env: EnvironmentInfo | null
  credential: CredentialFacts | null
}

const Picker = createContext<PickerContext | null>(null)

function usePicker() {
  const context = useContext(Picker)
  if (!context) throw new Error("CredentialPicker context missing")
  return context
}

/**
 * Every way to open a signer (sandbox A1, PFX, OS store, PKCS#11, CSC), shared by the PDF,
 * CAdES and XML pages. Credentials live on the server; the page keeps the id it gets back.
 */
export function CredentialPicker({ environment, env, credential, onCredential }: PickerContext & { onCredential: (facts: CredentialFacts) => void }) {
  const t = useT()
  const [tab, setTab] = useState(environment === "Sandbox" ? "sandbox" : "pfx")
  useEffect(() => setTab(environment === "Sandbox" ? "sandbox" : "pfx"), [environment])

  const opened = (facts: CredentialFacts) => {
    onCredential(facts)
    toast.success(t("signer.ready"), { description: `${facts.holder} · ${facts.source}` })
  }

  return (
    <Picker.Provider value={{ environment, env, credential }}>
      <div className="space-y-8">
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="grid h-auto! w-full grid-cols-2 gap-1 p-1 sm:grid-cols-3">
            {environment === "Sandbox" && <Tab value="sandbox" icon={<ShieldCheck />} label="signer.tabs.sandbox" info="signer.SandboxA1" />}
            <Tab value="pfx" icon={<FileKey2 />} label="signer.tabs.pfx" info="signer.Pfx" />
            <Tab value="store" icon={<MonitorSmartphone />} label="signer.tabs.store" info="signer.OsStore" />
            <Tab value="pkcs11" icon={<Usb />} label="signer.tabs.pkcs11" info="signer.Pkcs11" />
            <Tab value="csc" icon={<Cloud />} label="signer.tabs.csc" info="signer.Csc" />
          </TabsList>
          <div className="pt-5">
            <TabsContent value="sandbox"><SandboxSigners onOpened={opened} /></TabsContent>
            <TabsContent value="pfx"><PfxForm onOpened={opened} /></TabsContent>
            <TabsContent value="store"><StoreList onOpened={opened} /></TabsContent>
            <TabsContent value="pkcs11"><TokenList onOpened={opened} /></TabsContent>
            <TabsContent value="csc"><CscForm onOpened={opened} /></TabsContent>
          </div>
        </Tabs>
        {credential && <CredentialCard facts={credential} />}
      </div>
    </Picker.Provider>
  )
}

function Tab({ value, icon, label, info }: { value: string; icon: ReactNode; label: MessageKey; info: string }) {
  const t = useT()
  return (
    <TabsTrigger value={value} className="h-8 justify-start gap-1.5 px-3 [&_svg]:size-3.5">
      {icon}
      {t(label)}
      <Explain id={info} />
    </TabsTrigger>
  )
}

function SandboxSigners({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const { env, credential } = usePicker()
  const [busy, setBusy] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  if (!env) return <Loader2 className="size-4 animate-spin" />
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {env.signers.map((s) => (
        <ChoiceCard
          key={s.id}
          selected={selected === s.id && credential?.kind === "SandboxA1"}
          title={s.title}
          description={s.description}
          icon={busy === s.id ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
          badge={
            <span className="ml-auto flex gap-1">
              <Pill>{s.keyType.replace("Rsa", "RSA ").replace("EcdsaP", "P-")}</Pill>
              {s.problem && <Pill tone="warning">{s.problem}</Pill>}
            </span>
          }
          onSelect={async () => {
            setBusy(s.id)
            try {
              onOpened(await api.credentials.sandbox(s.id))
              setSelected(s.id)
            } finally {
              setBusy(null)
            }
          }}
        />
      ))}
    </div>
  )
}

function useAction() {
  const t = useT()
  const [busy, setBusy] = useState(false)
  const run = async (action: () => Promise<void>) => {
    setBusy(true)
    try {
      await action()
    } catch (e) {
      toast.error(t("signer.openFailed"), { description: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }
  return { busy, run }
}

function PfxForm({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState("")
  const { busy, run } = useAction()
  const t = useT()
  return (
    <div className="grid max-w-xl gap-4">
      <Field label={t("signer.pfx.file")} infoId="signer.Pfx">
        <Input type="file" accept=".pfx,.p12" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      </Field>
      <Field label={t("signer.pfx.password")} description={t("signer.pfx.passwordHint")}>
        <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
      </Field>
      <Button
        disabled={!file || busy}
        onClick={() =>
          run(async () => {
            const uploaded = await api.uploadFile(file!)
            onOpened(await api.credentials.pfx(uploaded.id, password))
            setPassword("")
          })
        }
        className="w-fit"
      >
        {busy && <Loader2 className="animate-spin" />} {t("signer.pfx.open")}
      </Button>
    </div>
  )
}

function StoreList({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const [items, setItems] = useState<StoreCertificate[] | null>(null)
  const { busy, run } = useAction()
  const t = useT()
  const load = () => api.credentials.store().then(setItems)
  useEffect(() => {
    load()
  }, [])
  if (!items) return <Loader2 className="size-4 animate-spin" />
  const usable = items.filter((c) => c.hasPrivateKey)
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground text-sm">{t("signer.store.count", { n: usable.length })}</p>
        <Button variant="ghost" size="sm" onClick={load}><RefreshCw /> {t("common.refresh")}</Button>
      </div>
      {usable.length === 0 && (
        <Alert>
          <AlertTitle>{t("signer.store.none")}</AlertTitle>
          <AlertDescription>{t("signer.store.noneHint")}</AlertDescription>
        </Alert>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        {usable.map((c) => (
          <ChoiceCard key={c.thumbprint} selected={false} title={c.holder} description={t("signer.validUntil", { issuer: c.issuer, date: c.notAfter })}
            onSelect={() => !busy && run(async () => onOpened(await api.credentials.openStore(c.thumbprint)))} icon={<MonitorSmartphone className="size-4" />} />
        ))}
      </div>
    </div>
  )
}

function TokenList({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const [drivers, setDrivers] = useState<Pkcs11Driver[] | null>(null)
  const [pin, setPin] = useState("")
  const [customLibrary, setCustomLibrary] = useState("")
  const { busy, run } = useAction()
  const t = useT()
  const load = () => {
    setDrivers(null)
    api.credentials.pkcs11().then(setDrivers).catch(() => setDrivers([]))
  }
  useEffect(load, [])
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <p className="text-muted-foreground text-sm">{t("signer.pkcs11.intro")}</p>
        <Button variant="ghost" size="sm" onClick={load}><RefreshCw /> {t("signer.pkcs11.rescan")}</Button>
      </div>
      {drivers === null && <Loader2 className="size-4 animate-spin" />}
      {drivers?.length === 0 && (
        <Alert>
          <Usb />
          <AlertTitle>{t("signer.pkcs11.none")}</AlertTitle>
          <AlertDescription>{t("signer.pkcs11.noneHint")}</AlertDescription>
        </Alert>
      )}
      <Field label="PIN" description={t("signer.pkcs11.pinHint")}>
        <Input type="password" value={pin} onChange={(e) => setPin(e.target.value)} className="max-w-xs" autoComplete="off" />
      </Field>
      {drivers?.map((d) => (
        <div key={d.libraryPath} className="space-y-2 rounded-lg border p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Usb className="size-4" /> {d.driver} <code className="text-muted-foreground font-mono text-xs">{d.libraryPath}</code>
          </div>
          {d.error && <p className="text-destructive text-xs">{d.error}</p>}
          {d.tokens.length === 0 && !d.error && <p className="text-muted-foreground text-xs">{t("signer.pkcs11.noToken")}</p>}
          {d.tokens.map((tok) => (
            <div key={tok.tokenSerial} className="space-y-2 pl-6">
              <p className="text-xs">
                Token <b>{tok.tokenLabel}</b> · serial {tok.tokenSerial} {tok.hasPinPad && <Pill>PIN pad</Pill>} {tok.pinLocked && <Pill tone="danger">{t("signer.pkcs11.locked")}</Pill>}
              </p>
              {tok.certificates.map((c) => (
                <ChoiceCard key={c.thumbprint} selected={false} title={c.holder} description={t("signer.validUntil", { issuer: c.issuer, date: c.notAfter })}
                  onSelect={() => !busy && run(async () => onOpened(await api.credentials.openPkcs11({ libraryPath: tok.libraryPath, tokenSerial: tok.tokenSerial, certificateThumbprint: c.thumbprint, pin, usePinPad: !pin && tok.hasPinPad })))} />
              ))}
            </div>
          ))}
        </div>
      ))}
      <Field label={t("signer.pkcs11.other")} description={t("signer.pkcs11.otherHint")}>
        <div className="flex gap-2">
          <Input value={customLibrary} onChange={(e) => setCustomLibrary(e.target.value)} placeholder="/usr/local/lib/softhsm/libsofthsm2.so" />
          <Button variant="outline" disabled={!customLibrary || busy} onClick={() => run(async () => onOpened(await api.credentials.openPkcs11({ libraryPath: customLibrary, pin, usePinPad: !pin })))}>{t("common.open")}</Button>
        </div>
      </Field>
    </div>
  )
}

/** What a CSC cloud certificate is and how a signature happens with it, step by step, with its standard. */
function CloudExplainer() {
  const t = useT()
  const steps = [1, 2, 3, 4].map((n) => t(`signer.cloud.csc.step${n}` as MessageKey))
  return (
    <div className="bg-muted/40 space-y-2 rounded-lg border p-3 text-sm">
      <p className="leading-relaxed">{t("signer.cloud.csc.what")}</p>
      <ol className="text-muted-foreground list-decimal space-y-0.5 pl-5 text-xs leading-relaxed">
        {steps.map((step) => <li key={step}>{step}</li>)}
      </ol>
      <p className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span className="rounded border px-1.5 py-px font-mono text-[10px]">CSC API v2.0</span>
        <code className="font-mono text-[11px] break-all">CscClient + CscSigner.CreateAsync → WithExternalSigner</code>
      </p>
    </div>
  )
}

function CscForm({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const { environment, env } = usePicker()
  const sandbox = environment === "Sandbox"
  const [form, setForm] = useState({ baseUrl: "", serviceAuth: "Token", accessToken: "", clientId: "", clientSecret: "", credentialId: "", authorizer: "Explicit", pin: "", otp: "", signaturesPerAuthorization: 1 })
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }))
  const [list, setList] = useState<CscCredentialSummary[] | null>(null)
  const { busy, run } = useAction()
  const t = useT()
  useEffect(() => {
    if (sandbox && env) setList(env.cscCredentials)
  }, [sandbox, env])
  const chosen = list?.find((c) => c.id === form.credentialId)
  return (
    <div className="grid max-w-3xl gap-5">
      <CloudExplainer />
      {sandbox ? (
        <Alert>
          <Cloud />
          <AlertTitle>{t("signer.csc.simulated")}</AlertTitle>
          <AlertDescription className="space-y-2">
            <span className="block break-words">{t("signer.csc.simulatedHint", { url: env?.cscUrl ?? "", pin: env?.cscPin ?? "", otp: env?.cscOtp ?? "" })}</span>
            <Button size="sm" disabled={busy} onClick={() => run(async () => onOpened(await api.credentials.csc(environment, {
              ...form, serviceAuth: "ClientCredentials", credentialId: "rsa-scal2", authorizer: "Explicit", pin: env?.cscPin, otp: env?.cscOtp,
            })))}>
              {busy && <Loader2 className="animate-spin" />} {t("signer.cloud.useSimulated")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <Field label={t("signer.csc.baseUrl")}><Input value={form.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://<qtsp>/csc/v2/" /></Field>
      )}
      <Section title={t("signer.csc.service")} description={t("signer.csc.serviceHint")}>
        <div className="grid gap-3 sm:grid-cols-3">
          <ChoiceCard selected={form.serviceAuth === "Token"} onSelect={() => set({ serviceAuth: "Token" })} title={t("signer.csc.token")} description={t("signer.csc.tokenHint")} />
          <ChoiceCard selected={form.serviceAuth === "ClientCredentials"} onSelect={() => set({ serviceAuth: "ClientCredentials" })} title={t("signer.csc.clientCredentials")} description={t("signer.csc.clientCredentialsHint")} />
          <ChoiceCard selected={form.serviceAuth === "OAuth"} onSelect={() => set({ serviceAuth: "OAuth" })} title={t("signer.csc.userLogin")} description={t("signer.csc.userLoginHint")} />
        </div>
        {!sandbox && (
          <div className="grid gap-4 sm:grid-cols-3">
            {form.serviceAuth === "Token" ? (
              <Field label={t("signer.csc.token")} className="sm:col-span-3"><Input type="password" value={form.accessToken} onChange={(e) => set({ accessToken: e.target.value })} autoComplete="off" /></Field>
            ) : (
              <>
                <Field label="client_id"><Input value={form.clientId} onChange={(e) => set({ clientId: e.target.value })} /></Field>
                <Field label="client_secret"><Input type="password" value={form.clientSecret} onChange={(e) => set({ clientSecret: e.target.value })} autoComplete="off" /></Field>
              </>
            )}
          </div>
        )}
        {!sandbox && (
          <Button variant="outline" className="w-fit" disabled={busy} onClick={() => run(async () => setList(await api.credentials.cscList(environment, form)))}>
            {t("signer.csc.list")}
          </Button>
        )}
      </Section>
      {list && (
        <Section title={t("signer.csc.credential")} description={t("signer.csc.credentialHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {list.map((c) => (
              <ChoiceCard key={c.id} selected={form.credentialId === c.id} onSelect={() => set({ credentialId: c.id, authorizer: c.authMode === "oauth2code" ? "OAuth" : "Explicit" })}
                title={c.id} description={c.holder}
                badge={<span className="ml-auto flex gap-1"><Pill>SCAL {c.scal}</Pill><Pill>{c.authMode}</Pill></span>} />
            ))}
          </div>
        </Section>
      )}
      {chosen && (
        <Section title={t("signer.csc.authorization")} description={t("signer.csc.authorizationHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            <ChoiceCard selected={form.authorizer === "Explicit"} onSelect={() => set({ authorizer: "Explicit" })} title="PIN / OTP" description="ExplicitCscAuthorizer" state={chosen.authMode === "oauth2code" ? { visible: true, disabled: t("signer.csc.oauthOnly") } : undefined} />
            <ChoiceCard selected={form.authorizer === "OAuth"} onSelect={() => set({ authorizer: "OAuth" })} title={t("signer.csc.oauth")} description={t("signer.csc.oauthHint")} />
          </div>
          {form.authorizer === "Explicit" && (
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="PIN"><Input type="password" value={form.pin} onChange={(e) => set({ pin: e.target.value })} autoComplete="off" /></Field>
              <Field label="OTP" description={chosen.scal === "2" ? t("signer.csc.otpRequired") : t("common.optional")}><Input value={form.otp} onChange={(e) => set({ otp: e.target.value })} autoComplete="off" /></Field>
              <Field label={t("signer.csc.perAuthorization")} description={t("signer.csc.perAuthorizationHint", { n: chosen.multiSign })}>
                <Input type="number" min={1} max={chosen.multiSign} value={form.signaturesPerAuthorization} onChange={(e) => set({ signaturesPerAuthorization: Number(e.target.value) })} />
              </Field>
            </div>
          )}
          <Button className="w-fit" disabled={busy} onClick={() => run(async () => onOpened(await api.credentials.csc(environment, form)))}>
            {busy && <Loader2 className="animate-spin" />} {t("signer.csc.load")}
          </Button>
        </Section>
      )}
    </div>
  )
}

export function CredentialCard({ facts }: { facts: CredentialFacts }) {
  const t = useT()
  return (
    <Section title={t("signer.card.title")} description={t("signer.card.hint")}>
      <div className="rounded-lg border">
        <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
          <KeyRound className="size-4" />
          <span className="font-medium">{facts.holder}</span>
          <span className="text-muted-foreground text-xs">{facts.source}</span>
          <span className="ml-auto flex flex-wrap gap-1">
            {facts.isExpired && <Pill tone="danger">{t("signer.card.expired")}</Pill>}
            {facts.isNotYetValid && <Pill tone="warning">{t("signer.card.notYetValid")}</Pill>}
            {!facts.hasNonRepudiation && <Pill tone="warning">{t("signer.card.noNonRepudiation")}</Pill>}
          </span>
        </div>
        <div className="grid gap-x-8 p-4 sm:grid-cols-2">
          <KeyValue label={t("signer.card.key")}>{facts.keyAlgorithm} {facts.keySize}</KeyValue>
          <KeyValue label={t("signer.card.valid")}>{facts.notBefore} → {facts.notAfter}</KeyValue>
          <KeyValue stacked label={t("signer.card.issuer")}>{facts.issuer}</KeyValue>
          <KeyValue stacked label={t("signer.card.digests")}>{facts.hashes.map((h) => h.replace("Sha3_", "SHA3-").replace("Sha", "SHA-")).join(", ")}</KeyValue>
          <KeyValue label={t("signer.card.schemes")}>{facts.keyAlgorithm === "RSA" ? facts.paddings.map((p) => (p === "Pss" ? "RSASSA-PSS" : "PKCS#1 v1.5")).join(", ") : "ECDSA"}</KeyValue>
        </div>
        {facts.notes.length > 0 && (
          <ul className="text-muted-foreground space-y-1 border-t px-4 py-3 text-xs">
            {facts.notes.map((n, i) => <li key={i}>• {n}</li>)}
          </ul>
        )}
      </div>
    </Section>
  )
}
