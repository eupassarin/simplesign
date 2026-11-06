import { useEffect, useState, type ReactNode } from "react"
import { Cloud, FileKey2, KeyRound, Loader2, MonitorSmartphone, RefreshCw, ShieldCheck, Usb } from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api } from "@/lib/api"
import type { CredentialFacts, CscCredentialSummary, Pkcs11Driver, StoreCertificate } from "@/lib/types"
import { ChoiceCard, Explain, Field, KeyValue, Pill, Section } from "../ui"
import { useSigning } from "../state"

export function SignerStep() {
  const { environment, credential, update } = useSigning()
  const [tab, setTab] = useState(environment === "Sandbox" ? "sandbox" : "pfx")
  useEffect(() => setTab(environment === "Sandbox" ? "sandbox" : "pfx"), [environment])

  const opened = (facts: CredentialFacts) => {
    update({ credentialId: facts.id })
    toast.success("Signer ready", { description: `${facts.holder} · ${facts.source}` })
  }

  return (
    <div className="space-y-8">
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="flex h-auto w-full flex-wrap justify-start gap-1 p-1">
          {environment === "Sandbox" && <Tab value="sandbox" icon={<ShieldCheck />} label="Sandbox A1" info="signer.SandboxA1" />}
          <Tab value="pfx" icon={<FileKey2 />} label="A1 (PFX)" info="signer.Pfx" />
          <Tab value="store" icon={<MonitorSmartphone />} label="OS store" info="signer.OsStore" />
          <Tab value="pkcs11" icon={<Usb />} label="A3 token" info="signer.Pkcs11" />
          <Tab value="psc" icon={<Cloud />} label="Cloud PSC" info="signer.Psc" />
          <Tab value="csc" icon={<Cloud />} label="Cloud CSC v2" info="signer.Csc" />
        </TabsList>
        <div className="pt-5">
          <TabsContent value="sandbox"><SandboxSigners onOpened={opened} /></TabsContent>
          <TabsContent value="pfx"><PfxForm onOpened={opened} /></TabsContent>
          <TabsContent value="store"><StoreList onOpened={opened} /></TabsContent>
          <TabsContent value="pkcs11"><TokenList onOpened={opened} /></TabsContent>
          <TabsContent value="psc"><PscForm onOpened={opened} /></TabsContent>
          <TabsContent value="csc"><CscForm onOpened={opened} /></TabsContent>
        </div>
      </Tabs>
      {credential && <CredentialCard facts={credential} />}
    </div>
  )
}

function Tab({ value, icon, label, info }: { value: string; icon: ReactNode; label: string; info: string }) {
  return (
    <TabsTrigger value={value} className="h-8 flex-none gap-1.5 px-3 [&_svg]:size-3.5">
      {icon}
      {label}
      <Explain id={info} />
    </TabsTrigger>
  )
}

function SandboxSigners({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const { env, credential } = useSigning()
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
  const [busy, setBusy] = useState(false)
  const run = async (action: () => Promise<void>) => {
    setBusy(true)
    try {
      await action()
    } catch (e) {
      toast.error("Could not open the signer", { description: (e as Error).message })
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
  return (
    <div className="grid max-w-xl gap-4">
      <Field label="PFX / P12 file" infoId="signer.Pfx">
        <Input type="file" accept=".pfx,.p12" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      </Field>
      <Field label="Password" description="Used once to open the file; never stored or logged.">
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
        {busy && <Loader2 className="animate-spin" />} Open certificate
      </Button>
    </div>
  )
}

function StoreList({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const [items, setItems] = useState<StoreCertificate[] | null>(null)
  const { busy, run } = useAction()
  const load = () => api.credentials.store().then(setItems)
  useEffect(() => {
    load()
  }, [])
  if (!items) return <Loader2 className="size-4 animate-spin" />
  const usable = items.filter((c) => c.hasPrivateKey)
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground text-sm">{usable.length} certificate(s) with a private key in the current user's store.</p>
        <Button variant="ghost" size="sm" onClick={load}><RefreshCw /> Refresh</Button>
      </div>
      {usable.length === 0 && (
        <Alert>
          <AlertTitle>No certificates with a private key</AlertTitle>
          <AlertDescription>Import a PFX into your keychain / Windows certificate store, or use the A1 (PFX) tab.</AlertDescription>
        </Alert>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        {usable.map((c) => (
          <ChoiceCard key={c.thumbprint} selected={false} title={c.holder} description={`${c.issuer} · valid until ${c.notAfter}`}
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
  const load = () => {
    setDrivers(null)
    api.credentials.pkcs11().then(setDrivers).catch(() => setDrivers([]))
  }
  useEffect(load, [])
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <p className="text-muted-foreground text-sm">Installed drivers of known ICP-Brasil tokens and SoftHSM, plus <code className="font-mono text-xs">$SIMPLESIGN_PKCS11_LIBRARY</code>. Listing needs no PIN.</p>
        <Button variant="ghost" size="sm" onClick={load}><RefreshCw /> Rescan</Button>
      </div>
      {drivers === null && <Loader2 className="size-4 animate-spin" />}
      {drivers?.length === 0 && (
        <Alert>
          <Usb />
          <AlertTitle>No PKCS#11 driver found</AlertTitle>
          <AlertDescription>
            Install your token's driver (SafeNet, Watchdata, GD…) or try SoftHSM2: <code className="font-mono text-xs">brew install softhsm</code> /{" "}
            <code className="font-mono text-xs">apt install softhsm2</code>, create a token with <code className="font-mono text-xs">softhsm2-util --init-token</code> and import a key.
          </AlertDescription>
        </Alert>
      )}
      <Field label="PIN" description="Sent once to log in to the token; the session stays open until you close the TestBench. Leave empty for a PIN-pad reader.">
        <Input type="password" value={pin} onChange={(e) => setPin(e.target.value)} className="max-w-xs" autoComplete="off" />
      </Field>
      {drivers?.map((d) => (
        <div key={d.libraryPath} className="space-y-2 rounded-lg border p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Usb className="size-4" /> {d.driver} <code className="text-muted-foreground font-mono text-xs">{d.libraryPath}</code>
          </div>
          {d.error && <p className="text-destructive text-xs">{d.error}</p>}
          {d.tokens.length === 0 && !d.error && <p className="text-muted-foreground text-xs">No token connected.</p>}
          {d.tokens.map((t) => (
            <div key={t.tokenSerial} className="space-y-2 pl-6">
              <p className="text-xs">
                Token <b>{t.tokenLabel}</b> · serial {t.tokenSerial} {t.hasPinPad && <Pill>PIN pad</Pill>} {t.pinLocked && <Pill tone="danger">PIN locked</Pill>}
              </p>
              {t.certificates.map((c) => (
                <ChoiceCard key={c.thumbprint} selected={false} title={c.holder} description={`${c.issuer} · until ${c.notAfter}`}
                  onSelect={() => !busy && run(async () => onOpened(await api.credentials.openPkcs11({ libraryPath: t.libraryPath, tokenSerial: t.tokenSerial, certificateThumbprint: c.thumbprint, pin, usePinPad: !pin && t.hasPinPad })))} />
              ))}
            </div>
          ))}
        </div>
      ))}
      <Field label="Other driver (library path)" description="Any PKCS#11 module; the first certificate with a key on the first token is used.">
        <div className="flex gap-2">
          <Input value={customLibrary} onChange={(e) => setCustomLibrary(e.target.value)} placeholder="/usr/local/lib/softhsm/libsofthsm2.so" />
          <Button variant="outline" disabled={!customLibrary || busy} onClick={() => run(async () => onOpened(await api.credentials.openPkcs11({ libraryPath: customLibrary, pin, usePinPad: !pin })))}>Open</Button>
        </div>
      </Field>
    </div>
  )
}

function PscForm({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const { environment, env } = useSigning()
  const sandbox = environment === "Sandbox"
  const [form, setForm] = useState({ baseUrl: "", clientId: "", clientSecret: "", flow: "Browser", cpf: "", otp: "", scope: "SignatureSession", alias: "" })
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }))
  const { busy, run } = useAction()
  return (
    <div className="grid max-w-2xl gap-4">
      {sandbox ? (
        <Alert>
          <Cloud />
          <AlertTitle>Simulated PSC</AlertTitle>
          <AlertDescription>
            {env?.pscUrl} — the provider's login page is approved automatically. CPF {env?.pscCpf}, OTP {env?.pscOtp}. Two certificates: maria-rsa2048 and empresa-ecnpj.
          </AlertDescription>
        </Alert>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="PSC API base URL" className="sm:col-span-2"><Input value={form.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://<provider>/v0/" /></Field>
          <Field label="client_id"><Input value={form.clientId} onChange={(e) => set({ clientId: e.target.value })} /></Field>
          <Field label="client_secret"><Input type="password" value={form.clientSecret} onChange={(e) => set({ clientSecret: e.target.value })} autoComplete="off" /></Field>
        </div>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <ChoiceCard selected={form.flow === "Browser"} onSelect={() => set({ flow: "Browser" })} title="Login in the browser" description="OAuth authorization code + PKCE. The provider's page opens; you approve with your app/OTP." />
        <ChoiceCard selected={form.flow === "Password"} onSelect={() => set({ flow: "Password" })} title="CPF + OTP" description="Password grant with the one-time code from the provider's app (when the PSC offers it)." />
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="CPF / CNPJ" description={form.flow === "Browser" ? "Optional login hint." : undefined}>
          <Input value={sandbox ? env?.pscCpf ?? "" : form.cpf} disabled={sandbox} onChange={(e) => set({ cpf: e.target.value })} />
        </Field>
        {form.flow === "Password" && (
          <Field label="OTP"><Input value={form.otp} placeholder={sandbox ? env?.pscOtp : ""} onChange={(e) => set({ otp: e.target.value })} autoComplete="off" /></Field>
        )}
        <Field label="Scope">
          <Select value={form.scope} onValueChange={(v) => set({ scope: v })}>
            <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="SignatureSession">signature_session</SelectItem>
              <SelectItem value="MultiSignature">multi_signature</SelectItem>
              <SelectItem value="SingleSignature">single_signature</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Certificate alias" description="Only when the account has more than one.">
          <Input value={form.alias} onChange={(e) => set({ alias: e.target.value })} placeholder={sandbox ? "maria-rsa2048" : ""} />
        </Field>
      </div>
      <Button className="w-fit" disabled={busy} onClick={() => run(async () => onOpened(await api.credentials.psc(environment, form.flow === "Password" ? "password" : "browser", { ...form, otp: form.otp || undefined })))}>
        {busy && <Loader2 className="animate-spin" />} Authorize and load certificate
      </Button>
    </div>
  )
}

function CscForm({ onOpened }: { onOpened: (f: CredentialFacts) => void }) {
  const { environment, env } = useSigning()
  const sandbox = environment === "Sandbox"
  const [form, setForm] = useState({ baseUrl: "", serviceAuth: "Token", accessToken: "", clientId: "", clientSecret: "", credentialId: "", authorizer: "Explicit", pin: "", otp: "", signaturesPerAuthorization: 1 })
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }))
  const [list, setList] = useState<CscCredentialSummary[] | null>(null)
  const { busy, run } = useAction()
  useEffect(() => {
    if (sandbox && env) setList(env.cscCredentials)
  }, [sandbox, env])
  const chosen = list?.find((c) => c.id === form.credentialId)
  return (
    <div className="grid max-w-3xl gap-5">
      {sandbox ? (
        <Alert>
          <Cloud />
          <AlertTitle>Simulated CSC v2 service</AlertTitle>
          <AlertDescription>{env?.cscUrl} — PIN {env?.cscPin}, OTP {env?.cscOtp} (SCAL 2). The OAuth page is approved automatically.</AlertDescription>
        </Alert>
      ) : (
        <Field label="CSC API base URL"><Input value={form.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://<qtsp>/csc/v2/" /></Field>
      )}
      <Section title="1. Service authorization" description="How the TestBench authenticates to the service to list credentials.">
        <div className="grid gap-3 sm:grid-cols-3">
          <ChoiceCard selected={form.serviceAuth === "Token"} onSelect={() => set({ serviceAuth: "Token" })} title="Access token" description="A service token you already have." />
          <ChoiceCard selected={form.serviceAuth === "ClientCredentials"} onSelect={() => set({ serviceAuth: "ClientCredentials" })} title="Client credentials" description="OAuth client id + secret." />
          <ChoiceCard selected={form.serviceAuth === "OAuth"} onSelect={() => set({ serviceAuth: "OAuth" })} title="User login" description="OAuth authorization code (service scope)." />
        </div>
        {!sandbox && (
          <div className="grid gap-4 sm:grid-cols-3">
            {form.serviceAuth === "Token" ? (
              <Field label="Access token" className="sm:col-span-3"><Input type="password" value={form.accessToken} onChange={(e) => set({ accessToken: e.target.value })} autoComplete="off" /></Field>
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
            List credentials
          </Button>
        )}
      </Section>
      {list && (
        <Section title="2. Credential" description="Each credential is a key + certificate; SCAL 2 binds each authorization to the exact hashes.">
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
        <Section title="3. Credential authorization" description="Per signature: credentials/authorize with PIN/OTP (returns a SAD), or OAuth with the credential scope.">
          <div className="grid gap-3 sm:grid-cols-2">
            <ChoiceCard selected={form.authorizer === "Explicit"} onSelect={() => set({ authorizer: "Explicit" })} title="PIN / OTP" description="ExplicitCscAuthorizer" state={chosen.authMode === "oauth2code" ? { visible: true, disabled: "This credential is authorized with OAuth (auth/mode = oauth2code)." } : undefined} />
            <ChoiceCard selected={form.authorizer === "OAuth"} onSelect={() => set({ authorizer: "OAuth" })} title="OAuth (credential scope)" description="OAuthCscAuthorizer: the user approves the hashes on the provider's page." />
          </div>
          {form.authorizer === "Explicit" && (
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="PIN"><Input type="password" value={form.pin} onChange={(e) => set({ pin: e.target.value })} autoComplete="off" /></Field>
              <Field label="OTP" description={chosen.scal === "2" ? "Required for SCAL 2." : "Optional."}><Input value={form.otp} onChange={(e) => set({ otp: e.target.value })} autoComplete="off" /></Field>
              <Field label="Signatures per authorization" description={`The credential allows up to ${chosen.multiSign}.`}>
                <Input type="number" min={1} max={chosen.multiSign} value={form.signaturesPerAuthorization} onChange={(e) => set({ signaturesPerAuthorization: Number(e.target.value) })} />
              </Field>
            </div>
          )}
          <Button className="w-fit" disabled={busy} onClick={() => run(async () => onOpened(await api.credentials.csc(environment, form)))}>
            {busy && <Loader2 className="animate-spin" />} Load credential
          </Button>
        </Section>
      )}
    </div>
  )
}

export function CredentialCard({ facts }: { facts: CredentialFacts }) {
  return (
    <Section title="Signer" description="What the library will sign with, and what this key can produce. The Cryptography step only offers these.">
      <div className="rounded-lg border">
        <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
          <KeyRound className="size-4" />
          <span className="font-medium">{facts.holder}</span>
          <span className="text-muted-foreground text-xs">{facts.source}</span>
          <span className="ml-auto flex flex-wrap gap-1">
            {facts.isExpired && <Pill tone="danger">expired</Pill>}
            {facts.isNotYetValid && <Pill tone="warning">not yet valid</Pill>}
            {!facts.hasNonRepudiation && <Pill tone="warning">no nonRepudiation</Pill>}
            {facts.chainsToIcpBrasil && <Pill tone="success">ICP-Brasil</Pill>}
          </span>
        </div>
        <div className="grid gap-x-8 p-4 sm:grid-cols-2">
          <KeyValue label="Key">{facts.keyAlgorithm} {facts.keySize}</KeyValue>
          <KeyValue label="Valid">{facts.notBefore} → {facts.notAfter}</KeyValue>
          {facts.cpf && <KeyValue label="CPF">{facts.cpf}</KeyValue>}
          {facts.cnpj && <KeyValue label="CNPJ">{facts.cnpj}</KeyValue>}
          <KeyValue label="Issuer">{facts.issuer}</KeyValue>
          <KeyValue label="Digests">{facts.hashes.map((h) => h.replace("Sha3_", "SHA3-").replace("Sha", "SHA-")).join(", ")}</KeyValue>
          <KeyValue label="Schemes">{facts.keyAlgorithm === "RSA" ? facts.paddings.map((p) => (p === "Pss" ? "RSASSA-PSS" : "PKCS#1 v1.5")).join(", ") : "ECDSA"}</KeyValue>
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
