import { useState } from "react"
import { Clock } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { EnvironmentInfo, OptionState, TimestampChoice, TsaProvider } from "@/lib/types"
import { ChoiceCard, Field } from "./ui"

const sandboxProviders: TsaProvider[] = ["Sandbox", "SandboxAuthenticated", "SandboxUntrusted", "SandboxRevoked", "SandboxExpired", "SandboxWrongName", "SandboxShortLived", "SandboxIofe", "SandboxNonQualified"]
const publicProviders: TsaProvider[] = ["DigiCert", "Sectigo", "FreeTsa", "Custom"]

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
        {[...(env?.sandbox ? sandboxProviders : []), ...publicProviders].map((p) => (
          <ChoiceCard key={p} selected={value.provider === p} title={t(`type.tsa.${p}` as MessageKey)} infoId={`tsa.${p}`} icon={<Clock className="size-4" />} state={state(`tsa.${p}`)}
            onSelect={() => set({ provider: p, auth: p === "SandboxAuthenticated" ? "None" : value.auth })} />
        ))}
      </div>
      {value.provider === "Custom" && (
        <Field label={t("type.tsaUrl")} description={t("type.tsaUrlHint")}>
          <Input value={value.url ?? ""} onChange={(e) => set({ url: e.target.value })} placeholder="https://tsa.example.com/tsr" className="font-mono" />
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
