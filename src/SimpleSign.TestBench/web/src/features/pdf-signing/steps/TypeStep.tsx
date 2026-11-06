import { useEffect, useState } from "react"
import { Clock, Landmark, Layers, ScrollText, Sparkles } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { api } from "@/lib/api"
import type { BaselineLevel, IcpPolicyKind, IcpVersion, TimestampChoice, TsaProvider } from "@/lib/types"
import { ChoiceCard, Field, Pill, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

const levels: { id: BaselineLevel; title: string; text: string }[] = [
  { id: "BB", title: "B-B", text: "Basic: the signature and the signing certificate reference." },
  { id: "BT", title: "B-T", text: "+ signature timestamp from a TSA." },
  { id: "BLT", title: "B-LT", text: "+ certificates and CRL/OCSP in the DSS." },
  { id: "BLTA", title: "B-LTA", text: "+ document timestamp over everything." },
]

const policies: { id: IcpPolicyKind; title: string; text: string; level: string }[] = [
  { id: "AdRb", title: "AD-RB", text: "Basic reference. Timestamp optional.", level: "B-B / B-T" },
  { id: "AdRt", title: "AD-RT", text: "Time reference: signature timestamp from an ACT.", level: "B-T" },
  { id: "AdRc", title: "AD-RC", text: "Complete references: DSS with validation data + document timestamp.", level: "B-LTA" },
  { id: "AdRa", title: "AD-RA", text: "Archive: AD-RC + policy artifacts (PA, LPA) in the DSS.", level: "B-LTA" },
]

export function TypeStep() {
  const { options, update, state, report } = useSigning()
  const level = report?.effective.level ?? options.level
  const needsTsa = state("timestamp").visible
  return (
    <div className="space-y-8">
      <Section title="Kind of signature" description="Three mutually exclusive routes. Each one shows only the settings it needs.">
        <div className="grid gap-3 md:grid-cols-3">
          <ChoiceCard selected={options.kind === "Baseline"} onSelect={() => update({ kind: "Baseline" })} title="PAdES baseline" description="ETSI B-B, B-T, B-LT, B-LTA." infoId="kind.Baseline" icon={<Layers className="size-4" />} state={state("kind.Baseline")} />
          <ChoiceCard selected={options.kind === "IcpBrasil"} onSelect={() => update({ kind: "IcpBrasil" })} title="ICP-Brasil policy" description="AD-RB, AD-RT, AD-RC, AD-RA (DOC-ICP-15.03)." infoId="kind.IcpBrasil" icon={<Landmark className="size-4" />} state={state("kind.IcpBrasil")} />
          <ChoiceCard selected={options.kind === "CustomPolicy"} onSelect={() => update({ kind: "CustomPolicy" })} title="Custom policy" description="Baseline + any signature-policy-identifier." infoId="kind.CustomPolicy" icon={<ScrollText className="size-4" />} state={state("kind.CustomPolicy")} />
        </div>
      </Section>

      {options.kind !== "IcpBrasil" && (
        <Section title="Level" description="Each level adds what a validator needs to check the signature later.">
          <div className="grid gap-3 sm:grid-cols-2">
            {levels.map((l) => (
              <ChoiceCard key={l.id} selected={options.level === l.id} onSelect={() => update({ level: l.id })} title={l.title} description={l.text} infoId={`level.${l.id}`} state={state(`level.${l.id}`)} />
            ))}
          </div>
        </Section>
      )}

      {options.kind === "IcpBrasil" && <IcpSection />}

      {options.kind === "CustomPolicy" && (
        <Section title="Signature policy" description="Written as the signature-policy-identifier signed attribute (OID, hash of the policy document, optional URI)." infoId="kind.CustomPolicy">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Policy OID"><Input value={options.customPolicy.oid} onChange={(e) => update((o) => ({ customPolicy: { ...o.customPolicy, oid: e.target.value } }))} className="font-mono" /></Field>
            <Field label="Hash algorithm">
              <Select value={options.customPolicy.hashAlgorithm} onValueChange={(v) => update((o) => ({ customPolicy: { ...o.customPolicy, hashAlgorithm: v as never } }))}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["Sha256", "Sha384", "Sha512"].map((h) => <SelectItem key={h} value={h}>{h.replace("Sha", "SHA-")}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Policy hash (hex)" className="sm:col-span-2" description="The digest of the policy document, as published with the policy.">
              <Input value={options.customPolicy.hashHex} onChange={(e) => update((o) => ({ customPolicy: { ...o.customPolicy, hashHex: e.target.value.trim() } }))} className="font-mono" placeholder="e.g. 5A9E…" />
            </Field>
            <Field label="Policy URI (SPuri)" className="sm:col-span-2"><Input value={options.customPolicy.uri ?? ""} onChange={(e) => update((o) => ({ customPolicy: { ...o.customPolicy, uri: e.target.value } }))} /></Field>
          </div>
        </Section>
      )}

      {needsTsa && (
        <Section title="Timestamp" description={`Needed for ${report?.effectiveLevel ?? level}.`} infoId="timestamp">
          <TsaPicker value={options.timestamp} onChange={(timestamp) => update({ timestamp })} />
        </Section>
      )}

      {state("archiveTimestamp").visible && (
        <Section title="Archive timestamp" description="The document timestamp of B-LTA / AD-RC / AD-RA." infoId="archiveTimestamp">
          <ToggleRow checked={options.separateArchiveTsa} onChange={(separateArchiveTsa) => update({ separateArchiveTsa })} label="Use a separate archive TSA"
            description="Off: the signature TSA (and its credentials) is reused (ArchiveTimestampOptions = null)." />
          {options.separateArchiveTsa && <TsaPicker value={options.archiveTimestamp} onChange={(archiveTimestamp) => update({ archiveTimestamp })} />}
        </Section>
      )}

      <ToggleRow checked={options.returnLowerLevel} onChange={(returnLowerLevel) => update({ returnLowerLevel })} state={state("returnLowerLevel")} infoId="returnLowerLevel"
        label="Sign at a lower level if the TSA or revocation fails" description="SigningLevelFailureBehavior.ReturnLowerLevel: the result reports requested vs achieved level instead of throwing." />
    </div>
  )
}

function IcpSection() {
  const { options, update, state, credential, environment } = useSigning()
  const [versions, setVersions] = useState<IcpVersion[] | null>(null)
  useEffect(() => {
    setVersions(null)
    api.icpVersions(options.icpPolicy, options.credentialId).then(setVersions).catch(() => setVersions([]))
  }, [options.icpPolicy, options.credentialId])
  const auto = versions?.find((v) => v.isAutomatic)
  return (
    <>
      <Section title="Policy" description="All four PAdES policies; the sub-filter is fixed to PBAD.PAdES and the level follows the policy.">
        <div className="grid gap-3 sm:grid-cols-2">
          {policies.map((p) => (
            <ChoiceCard key={p.id} selected={options.icpPolicy === p.id} onSelect={() => update({ icpPolicy: p.id, icpVersionOid: null })} title={p.title} description={p.text} infoId={`icp.${p.id}`}
              badge={<Pill>{p.level}</Pill>} />
          ))}
        </div>
        <ToggleRow checked={options.icpAdRbTimestamp} onChange={(icpAdRbTimestamp) => update({ icpAdRbTimestamp })} state={state("icp.adrbTimestamp")} infoId="icp.adrbTimestamp"
          label="Add a signature timestamp" description="AD-RB with a timestamp is a B-T signature that still claims AD-RB." />
      </Section>
      <Section title="Policy version" infoId="icp.version"
        description={environment === "Sandbox" ? "Sandbox certificates do not chain to a real AC Raiz, so automatic picks the newest version in force." : credential?.chainsToIcpBrasil ? "Automatic picks the newest version that accepts your certificate's AC Raiz." : "Your certificate does not chain to ICP-Brasil: automatic picks the newest version in force."}>
        <div className="grid gap-3">
          <ChoiceCard selected={!options.icpVersionOid} onSelect={() => update({ icpVersionOid: null })} title="Automatic" icon={<Sparkles className="size-4" />}
            description={auto ? `Uses ${auto.oid} (v${auto.version}).` : "Picked by the signer's root when signing."} />
          {versions?.map((v) => (
            <ChoiceCard key={v.oid} selected={options.icpVersionOid === v.oid} onSelect={() => update({ icpVersionOid: v.oid })}
              title={<span className="font-mono text-xs">{v.oid}</span>}
              badge={<span className="ml-auto flex gap-1"><Pill>v{v.version}</Pill>{v.inForce ? <Pill tone="success">in force</Pill> : <Pill tone="danger">{v.revokedAt ? "revoked" : "expired"}</Pill>}{v.isAutomatic && <Pill tone="info">automatic</Pill>}</span>}
              description={`Signing period ${v.notBefore} → ${v.notAfter}. Accepts ${v.acceptedRoots.length} AC Raiz: ${v.acceptedRoots.map(shortRoot).join(", ") || "—"}.`}
              state={{ visible: true, disabled: v.disabled }}>
              <ul className="text-muted-foreground space-y-0.5 text-xs">{v.requirements.map((r) => <li key={r}>• {r}</li>)}</ul>
            </ChoiceCard>
          ))}
        </div>
      </Section>
    </>
  )
}

function shortRoot(subject: string) {
  const cn = /CN=([^,]+)/.exec(subject)?.[1] ?? subject
  return cn.replace("Autoridade Certificadora Raiz Brasileira", "AC Raiz")
}

const providers: { id: TsaProvider; title: string }[] = [
  { id: "Sandbox", title: "Sandbox TSA" },
  { id: "SandboxAuthenticated", title: "Sandbox (Basic auth)" },
  { id: "DigiCert", title: "DigiCert" },
  { id: "Sectigo", title: "Sectigo" },
  { id: "FreeTsa", title: "FreeTSA" },
  { id: "Custom", title: "Custom URL" },
]

function TsaPicker({ value, onChange }: { value: TimestampChoice; onChange: (v: TimestampChoice) => void }) {
  const { state, env } = useSigning()
  const set = (patch: Partial<TimestampChoice>) => onChange({ ...value, ...patch })
  const [uploading, setUploading] = useState(false)
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-3">
        {providers.map((p) => (
          <ChoiceCard key={p.id} selected={value.provider === p.id} title={p.title} infoId={`tsa.${p.id}`} icon={<Clock className="size-4" />} state={state(`tsa.${p.id}`)}
            onSelect={() => set(p.id === "SandboxAuthenticated" ? { provider: p.id, auth: "Basic", user: env?.tsaUser, password: env?.tsaPassword } : { provider: p.id })} />
        ))}
      </div>
      {value.provider === "Custom" && (
        <Field label="TSA URL" description="http://, https:// or tcp:// (RFC 3161 TCP transport).">
          <Input value={value.url ?? ""} onChange={(e) => set({ url: e.target.value })} placeholder="https://act.example.com.br/tsa" className="font-mono" />
        </Field>
      )}
      <div className="grid gap-4 rounded-lg border p-4 sm:grid-cols-3">
        <Field label="Authentication" infoId="tsa.auth">
          <Select value={value.auth} onValueChange={(v) => set({ auth: v as TimestampChoice["auth"] })}>
            <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="None">None</SelectItem>
              <SelectItem value="Basic">Basic (user + password)</SelectItem>
              <SelectItem value="Bearer">Bearer token</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        {value.auth === "Basic" && (
          <>
            <Field label="User"><Input value={value.user ?? ""} onChange={(e) => set({ user: e.target.value })} /></Field>
            <Field label="Password"><Input type="password" value={value.password ?? ""} onChange={(e) => set({ password: e.target.value })} autoComplete="off" /></Field>
          </>
        )}
        {value.auth === "Bearer" && (
          <Field label="Token" className="sm:col-span-2"><Input type="password" value={value.token ?? ""} onChange={(e) => set({ token: e.target.value })} autoComplete="off" /></Field>
        )}
        <Field label="TLS client certificate (PFX)" className="sm:col-span-3" description={state("tsa.clientCertificate").note ?? "For TSAs that require mutual TLS."}>
          <div className="flex flex-wrap gap-2">
            <Input type="file" accept=".pfx,.p12" className="max-w-xs" disabled={uploading}
              onChange={async (e) => {
                const file = e.target.files?.[0]
                if (!file) return set({ clientCertificateUploadId: null })
                setUploading(true)
                try {
                  set({ clientCertificateUploadId: (await api.uploadFile(file)).id })
                } finally {
                  setUploading(false)
                }
              }} />
            {value.clientCertificateUploadId && (
              <Input type="password" placeholder="PFX password" className="max-w-xs" value={value.clientCertificatePassword ?? ""} onChange={(e) => set({ clientCertificatePassword: e.target.value })} autoComplete="off" />
            )}
          </div>
        </Field>
      </div>
    </div>
  )
}
