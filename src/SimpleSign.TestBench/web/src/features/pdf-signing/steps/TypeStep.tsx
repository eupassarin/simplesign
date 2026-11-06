import { useEffect, useState } from "react"
import { Clock, Landmark, Layers, ScrollText, Sparkles } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { BaselineLevel, EnvironmentInfo, IcpPolicyKind, IcpVersion, OptionState, TimestampChoice, TsaProvider } from "@/lib/types"
import { ChoiceCard, Field, Pill, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

export const levels: { id: BaselineLevel; title: string }[] = [
  { id: "BB", title: "B-B" },
  { id: "BT", title: "B-T" },
  { id: "BLT", title: "B-LT" },
  { id: "BLTA", title: "B-LTA" },
]

const policies: { id: IcpPolicyKind; title: string; level: string }[] = [
  { id: "AdRb", title: "AD-RB", level: "B-B / B-T" },
  { id: "AdRt", title: "AD-RT", level: "B-T" },
  { id: "AdRc", title: "AD-RC", level: "B-LTA" },
  { id: "AdRa", title: "AD-RA", level: "B-LTA" },
]

export function TypeStep() {
  const { options, update, state, report, env } = useSigning()
  const level = report?.effective.level ?? options.level
  const needsTsa = state("timestamp").visible
  const t = useT()
  return (
    <div className="space-y-8">
      <Section title={t("type.kind")} description={t("type.kindHint")}>
        <div className="grid gap-3 md:grid-cols-3">
          <ChoiceCard selected={options.kind === "Baseline"} onSelect={() => update({ kind: "Baseline" })} title="PAdES baseline" description={t("type.baselineHint")} infoId="kind.Baseline" icon={<Layers className="size-4" />} state={state("kind.Baseline")} />
          <ChoiceCard selected={options.kind === "IcpBrasil"} onSelect={() => update({ kind: "IcpBrasil" })} title={t("type.icp")} description={t("type.icpHint")} infoId="kind.IcpBrasil" icon={<Landmark className="size-4" />} state={state("kind.IcpBrasil")} />
          <ChoiceCard selected={options.kind === "CustomPolicy"} onSelect={() => update({ kind: "CustomPolicy" })} title={t("type.custom")} description={t("type.customHint")} infoId="kind.CustomPolicy" icon={<ScrollText className="size-4" />} state={state("kind.CustomPolicy")} />
        </div>
      </Section>

      {options.kind !== "IcpBrasil" && (
        <Section title={t("type.level")} description={t("type.levelHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {levels.map((l) => (
              <ChoiceCard key={l.id} selected={options.level === l.id} onSelect={() => update({ level: l.id })} title={l.title} description={t(`type.levels.${l.id}` as MessageKey)} infoId={`level.${l.id}`} state={state(`level.${l.id}`)} />
            ))}
          </div>
        </Section>
      )}

      {options.kind === "IcpBrasil" && <IcpSection />}

      {options.kind === "CustomPolicy" && (
        <Section title={t("type.policy")} description={t("type.policyHint")} infoId="kind.CustomPolicy">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("type.policyOid")}><Input value={options.customPolicy.oid} onChange={(e) => update((o) => ({ customPolicy: { ...o.customPolicy, oid: e.target.value } }))} className="font-mono" /></Field>
            <Field label={t("type.hashAlgorithm")}>
              <Select value={options.customPolicy.hashAlgorithm} onValueChange={(v) => update((o) => ({ customPolicy: { ...o.customPolicy, hashAlgorithm: v as never } }))}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["Sha256", "Sha384", "Sha512"].map((h) => <SelectItem key={h} value={h}>{h.replace("Sha", "SHA-")}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("type.policyHash")} className="sm:col-span-2" description={t("type.policyHashHint")}>
              <Input value={options.customPolicy.hashHex} onChange={(e) => update((o) => ({ customPolicy: { ...o.customPolicy, hashHex: e.target.value.trim() } }))} className="font-mono" placeholder={t("type.policyHashPlaceholder")} />
            </Field>
            <Field label={t("type.policyUri")} className="sm:col-span-2"><Input value={options.customPolicy.uri ?? ""} onChange={(e) => update((o) => ({ customPolicy: { ...o.customPolicy, uri: e.target.value } }))} /></Field>
          </div>
        </Section>
      )}

      {needsTsa && (
        <Section title={t("type.timestamp")} description={t("type.timestampHint", { level: report?.effectiveLevel ?? level })} infoId="timestamp">
          <TsaPicker value={options.timestamp} onChange={(timestamp) => update({ timestamp })} state={state} env={env} />
        </Section>
      )}

      {state("archiveTimestamp").visible && (
        <Section title={t("type.archive")} description={t("type.archiveHint")} infoId="archiveTimestamp">
          <ToggleRow checked={options.separateArchiveTsa} onChange={(separateArchiveTsa) => update({ separateArchiveTsa })} label={t("type.separateArchive")}
            description={t("type.separateArchiveHint")} />
          {options.separateArchiveTsa && <TsaPicker value={options.archiveTimestamp} onChange={(archiveTimestamp) => update({ archiveTimestamp })} state={state} env={env} />}
        </Section>
      )}

      <ToggleRow checked={options.returnLowerLevel} onChange={(returnLowerLevel) => update({ returnLowerLevel })} state={state("returnLowerLevel")} infoId="returnLowerLevel"
        label={t("type.lowerLevel")} description={t("type.lowerLevelHint")} />
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
  const t = useT()
  return (
    <>
      <Section title={t("type.icpPolicy")} description={t("type.icpPolicyHint")}>
        <div className="grid gap-3 sm:grid-cols-2">
          {policies.map((p) => (
            <ChoiceCard key={p.id} selected={options.icpPolicy === p.id} onSelect={() => update({ icpPolicy: p.id, icpVersionOid: null })} title={p.title} description={t(`type.policies.${p.id}` as MessageKey)} infoId={`icp.${p.id}`}
              badge={<Pill>{p.level}</Pill>} />
          ))}
        </div>
        <ToggleRow checked={options.icpAdRbTimestamp} onChange={(icpAdRbTimestamp) => update({ icpAdRbTimestamp })} state={state("icp.adrbTimestamp")} infoId="icp.adrbTimestamp"
          label={t("type.adrbTimestamp")} description={t("type.adrbTimestampHint")} />
      </Section>
      <Section title={t("type.version")} infoId="icp.version"
        description={t(environment === "Sandbox" ? "type.versionSandbox" : credential?.chainsToIcpBrasil ? "type.versionIcp" : "type.versionOther")}>
        <div className="grid gap-3">
          <ChoiceCard selected={!options.icpVersionOid} onSelect={() => update({ icpVersionOid: null })} title={t("type.automatic")} icon={<Sparkles className="size-4" />}
            description={auto ? t("type.automaticUses", { oid: auto.oid, version: auto.version }) : t("type.automaticHint")} />
          {versions?.map((v) => (
            <ChoiceCard key={v.oid} selected={options.icpVersionOid === v.oid} onSelect={() => update({ icpVersionOid: v.oid })}
              title={<span className="font-mono text-xs">{v.oid}</span>}
              badge={<span className="ml-auto flex gap-1"><Pill>v{v.version}</Pill>{v.inForce ? <Pill tone="success">{t("type.inForce")}</Pill> : <Pill tone="danger">{t(v.revokedAt ? "type.revoked" : "type.expired")}</Pill>}{v.isAutomatic && <Pill tone="info">{t("type.automaticBadge")}</Pill>}</span>}
              description={t("type.versionDescription", { from: v.notBefore, to: v.notAfter, n: v.acceptedRoots.length, roots: v.acceptedRoots.map(shortRoot).join(", ") || "—" })}
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

const providers: TsaProvider[] = ["Sandbox", "SandboxAuthenticated", "DigiCert", "Sectigo", "FreeTsa", "Custom"]

export function TsaPicker({ value, onChange, state, env }: {
  value: TimestampChoice
  onChange: (v: TimestampChoice) => void
  state: (key: string) => OptionState
  env: EnvironmentInfo | null
}) {
  const set = (patch: Partial<TimestampChoice>) => onChange({ ...value, ...patch })
  const [uploading, setUploading] = useState(false)
  const t = useT()
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-3">
        {providers.map((p) => (
          <ChoiceCard key={p} selected={value.provider === p} title={t(`type.tsa.${p}` as MessageKey)} infoId={`tsa.${p}`} icon={<Clock className="size-4" />} state={state(`tsa.${p}`)}
            onSelect={() => set(p === "SandboxAuthenticated" ? { provider: p, auth: "Basic", user: env?.tsaUser, password: env?.tsaPassword } : { provider: p })} />
        ))}
      </div>
      {value.provider === "Custom" && (
        <Field label={t("type.tsaUrl")} description={t("type.tsaUrlHint")}>
          <Input value={value.url ?? ""} onChange={(e) => set({ url: e.target.value })} placeholder="https://act.example.com.br/tsa" className="font-mono" />
        </Field>
      )}
      <div className="grid gap-4 rounded-lg border p-4 sm:grid-cols-3">
        <Field label={t("type.auth")} infoId="tsa.auth">
          <Select value={value.auth} onValueChange={(v) => set({ auth: v as TimestampChoice["auth"] })}>
            <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="None">{t("type.authNone")}</SelectItem>
              <SelectItem value="Basic">{t("type.authBasic")}</SelectItem>
              <SelectItem value="Bearer">{t("type.authBearer")}</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        {value.auth === "Basic" && (
          <>
            <Field label={t("type.user")}><Input value={value.user ?? ""} onChange={(e) => set({ user: e.target.value })} /></Field>
            <Field label={t("type.password")}><Input type="password" value={value.password ?? ""} onChange={(e) => set({ password: e.target.value })} autoComplete="off" /></Field>
          </>
        )}
        {value.auth === "Bearer" && (
          <Field label="Token" className="sm:col-span-2"><Input type="password" value={value.token ?? ""} onChange={(e) => set({ token: e.target.value })} autoComplete="off" /></Field>
        )}
        <Field label={t("type.clientCertificate")} className="sm:col-span-3" description={state("tsa.clientCertificate").note ?? t("type.clientCertificateHint")}>
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
              <Input type="password" placeholder={t("type.pfxPassword")} className="max-w-xs" value={value.clientCertificatePassword ?? ""} onChange={(e) => set({ clientCertificatePassword: e.target.value })} autoComplete="off" />
            )}
          </div>
        </Field>
      </div>
    </div>
  )
}
