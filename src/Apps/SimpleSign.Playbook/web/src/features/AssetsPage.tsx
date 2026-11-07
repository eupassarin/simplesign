import { useRef, useState } from "react"
import { KeyRound, Trash2, Upload } from "lucide-react"
import { toast } from "sonner"
import { Pill, Section } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { WorkspaceView } from "@/lib/types"

/** The workspace's files (documents, certificates) and the passwords the playbook names. */
export function AssetsPage({ workspace, onChanged }: { workspace: WorkspaceView; onChanged: (w: WorkspaceView) => void }) {
  const { t, number, date } = useI18n()
  const input = useRef<HTMLInputElement>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const act = async (action: () => Promise<WorkspaceView>, done?: string) => {
    try {
      onChanged(await action())
      if (done) toast.success(done)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const named = (workspace.playbook?.assets ?? []).map((a) => a.secret).filter((s): s is string => !!s)
  const keys = [...new Set([...named, ...workspace.secretKeys])].sort()

  return (
    <div className="max-w-4xl space-y-8">
      <Section title={t("assets.title")} description={t("assets.intro")}
        aside={
          <>
            <input ref={input} type="file" multiple className="hidden" onChange={(e) => {
              if (e.target.files?.length) void act(() => api.uploadAssets(e.target.files!))
              e.target.value = ""
            }} />
            <Button size="sm" onClick={() => input.current?.click()}><Upload /> {t("assets.upload")}</Button>
          </>
        }>
        {workspace.assets.length === 0 ? <p className="text-muted-foreground text-sm">{t("assets.empty")}</p> : (
          <ul className="divide-y rounded-md border">
            {workspace.assets.map((a) => {
              const used = workspace.playbook?.assets?.find((d) => d.file === a.path)
              return (
                <li key={a.path} className="space-y-1 px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{a.path}</span>
                    {used && <Pill tone="info">{"${asset." + used.id + "}"}</Pill>}
                    <span className="text-muted-foreground text-xs">{t("assets.bytes", { size: number(a.bytes / 1024, 1) })}</span>
                    <Button variant="ghost" size="icon" className="ml-auto size-7" aria-label={t("common.delete")}
                      onClick={() => act(() => api.deleteAsset(a.path))}><Trash2 className="size-3.5" /></Button>
                  </div>
                  {a.certificate && (
                    <div className="text-muted-foreground grid gap-x-4 text-xs sm:grid-cols-2">
                      <span>{t("assets.subject")}: <span className="text-foreground">{a.certificate.subject}</span></span>
                      <span>{t("assets.issuer")}: <span className="text-foreground">{a.certificate.issuer}</span></span>
                      <span>{t("assets.valid")}: {date(a.certificate.notBefore)} → {date(a.certificate.notAfter)}</span>
                      <span>{t("assets.key")}: {a.certificate.keyAlgorithm}{a.certificate.hasPrivateKey ? `, ${t("assets.privateKey")}` : ""}</span>
                    </div>
                  )}
                  {a.certificateProblem && <p className="text-warning text-xs">{a.certificateProblem}</p>}
                </li>
              )
            })}
          </ul>
        )}
      </Section>

      <Section title={t("assets.secrets")} description={t("assets.secretsHint")}>
        {keys.length === 0 ? <p className="text-muted-foreground text-sm">{t("common.none")}</p> : (
          <ul className="divide-y rounded-md border">
            {keys.map((key) => (
              <li key={key} className="flex flex-wrap items-center gap-2 px-3 py-2">
                <KeyRound className="text-muted-foreground size-4" />
                <span className="w-40 font-mono text-xs">{key}</span>
                {workspace.secretKeys.includes(key) && <Pill tone="success">{t("assets.isSet")}</Pill>}
                <Input type="password" className="h-8 w-56" placeholder={t("assets.secretValue")} value={values[key] ?? ""}
                  onChange={(e) => setValues({ ...values, [key]: e.target.value })} autoComplete="off" />
                <Button size="sm" variant="outline" disabled={!values[key]} onClick={() => {
                  void act(() => api.setSecret(key, values[key]), t("common.saved"))
                  setValues({ ...values, [key]: "" })
                }}>{t("assets.setSecret")}</Button>
                {workspace.secretKeys.includes(key) && (
                  <Button size="sm" variant="ghost" onClick={() => act(() => api.setSecret(key, null))}>{t("common.remove")}</Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  )
}
