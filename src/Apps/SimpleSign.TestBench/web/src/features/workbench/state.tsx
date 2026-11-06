import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { toast } from "sonner"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { CredentialFacts, EnvironmentInfo, EnvironmentMode, OptionState } from "@/lib/types"
import {
  asText, getPath, hasPath, setPath,
  type DssSettings, type DssStatus, type Evaluation, type Format, type Options, type RunEvent, type RunKind, type RunLogEntry, type RunSummary,
  type RunView, type SchemaOption, type SchemaPreset, type SchemaValue, type WorkbenchSchema,
} from "./schema"

const shown: OptionState = { visible: true }

interface Slot {
  run: RunView | null
  logs: RunLogEntry[]
  running: boolean
}

const emptySlot: Slot = { run: null, logs: [], running: false }

/** The file being validated and, for a detached signature, its data. */
export interface ValidateTarget {
  fileId: string
  name: string
  dataId?: string | null
  dataName?: string | null
}

interface WorkbenchValue {
  /** The task on screen: make a signature, or validate a file. Each keeps its own result. */
  mode: RunKind
  setMode: (mode: RunKind) => void
  validateTarget: ValidateTarget | null
  setValidateTarget: (target: ValidateTarget | null) => void
  /** The trust and revocation settings of the Validate task, shaped like the options ({ validation: … }). */
  validateOptions: Options
  setValidateOption: (path: string, value: unknown) => void
  validate: (target?: ValidateTarget) => Promise<RunView | null>
  /** Shows a file in the Validate task and validates it. */
  openInValidate: (target: ValidateTarget) => void
  schema: WorkbenchSchema
  env: EnvironmentInfo | null
  environment: EnvironmentMode
  format: Format
  setFormat: (format: Format) => void
  /** The trust frameworks switched on (none by default). */
  frameworks: ReadonlySet<string>
  toggleFramework: (id: string) => void
  /** The options of the current format. */
  options: Options
  set: (path: string, value: unknown) => void
  patch: (values: Record<string, unknown>) => void
  applyPreset: (preset: SchemaPreset) => void
  reset: () => void
  evaluation: Evaluation | null
  evaluating: boolean
  state: (key: string) => OptionState
  credential: CredentialFacts | null
  /** Whether the option is shown for the current format, frameworks, conditions and rules. */
  isVisible: (option: SchemaOption) => boolean
  /** The values of a choice that can be offered now. */
  visibleValues: (option: SchemaOption) => SchemaValue[]
  // Runs
  run: RunView | null
  logs: RunLogEntry[]
  running: boolean
  sign: (overrides?: Options) => Promise<RunView | null>
  history: RunSummary[]
  openRun: (id: string) => Promise<void>
  reuse: (run: RunView) => void
  // Variants: the same options with every value of one option
  variants: Variants | null
  variantsRunning: boolean
  runVariants: (option: SchemaOption) => Promise<void>
  stopVariants: () => void
  // DSS
  dss: DssSettings
  dssStatus: DssStatus | null
  saveDss: (settings: DssSettings) => Promise<void>
  checkDss: () => Promise<void>
}

export interface VariantRow {
  value: string
  title: string
  status: "pending" | "running" | "done" | "skipped"
  /** Why the value was not run (the rules refuse the combination). */
  reason?: string
  run?: RunView
}

export interface Variants {
  option: SchemaOption
  format: Format
  rows: VariantRow[]
}

const Context = createContext<WorkbenchValue | null>(null)

function load<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}

/** The defaults of a format for an environment: the server's defaults, with the environment and its trusted roots. */
function initial(schema: WorkbenchSchema, format: Format, environment: EnvironmentMode, frameworks: ReadonlySet<string>): Options {
  let options: Options = structuredClone(schema.defaults[format])
  options = setPath(options, "environment", environment)
  options = setPath(options, "validation.environment", environment)
  options = setPath(options, "validation.trust", environment === "Sandbox" ? ["Sandbox"] : frameworks.has("brazil") ? ["System", "IcpBrasil"] : ["System"])
  options = setPath(options, "validation.useBrasil", frameworks.has("brazil"))
  return options
}

/** Puts back the default of every option (or value) that belongs to a framework that is switched off. */
function withoutFrameworks(schema: WorkbenchSchema, format: Format, options: Options, frameworks: ReadonlySet<string>): Options {
  const off = (framework?: string | null) => !!framework && !frameworks.has(framework)
  let next = options
  for (const option of schema.options) {
    if (!option.path || !option.formats.includes(format) || !hasPath(next, option.path)) continue
    const fallback = getPath(schema.defaults[format], option.path)
    const current = getPath(next, option.path)
    if (off(option.framework)) {
      next = setPath(next, option.path, fallback)
    } else if (Array.isArray(current)) {
      const banned = option.values.filter((v) => off(v.framework)).map((v) => v.value)
      if (current.some((v) => banned.includes(asText(v)))) next = setPath(next, option.path, current.filter((v) => !banned.includes(asText(v))))
    } else if (option.values.some((v) => off(v.framework) && v.value === asText(current))) {
      next = setPath(next, option.path, fallback)
    }
  }
  return next
}

export function WorkbenchProvider({ schema, environment, children }: { schema: WorkbenchSchema; environment: EnvironmentMode; children: ReactNode }) {
  const { t } = useI18n()
  const [env, setEnv] = useState<EnvironmentInfo | null>(null)
  const [format, setFormatState] = useState<Format>(() => load<Format>("wb.format", "pades"))
  const [frameworks, setFrameworks] = useState<ReadonlySet<string>>(() => new Set(load<string[]>("wb.frameworks", [])))
  const [byFormat, setByFormat] = useState<Record<Format, Options>>(() => ({
    pades: initial(schema, "pades", environment, frameworks),
    cades: initial(schema, "cades", environment, frameworks),
    xades: initial(schema, "xades", environment, frameworks),
  }))
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const [mode, setModeState] = useState<RunKind>(() => load<RunKind>("wb.mode", "sign"))
  const [slots, setSlots] = useState<Record<RunKind, Slot>>({ sign: emptySlot, validate: emptySlot })
  const patchSlot = useCallback((kind: RunKind, change: (slot: Slot) => Slot) => setSlots((all) => ({ ...all, [kind]: change(all[kind]) })), [])
  const { run, logs, running } = slots[mode]
  const [validateTarget, setValidateTarget] = useState<ValidateTarget | null>(null)
  const [validateOptions, setValidateOptions] = useState<Options>(() => ({ validate: true, validation: initial(schema, "pades", environment, frameworks).validation }))
  const setMode = useCallback((next: RunKind) => {
    localStorage.setItem("wb.mode", JSON.stringify(next))
    setModeState(next)
  }, [])
  const setValidateOption = useCallback((path: string, value: unknown) => setValidateOptions((o) => setPath(o, path, value)), [])
  const [history, setHistory] = useState<RunSummary[]>([])
  const [dss, setDss] = useState<DssSettings>({ enabled: false, url: "http://localhost:8080" })
  const [dssStatus, setDssStatus] = useState<DssStatus | null>(null)
  const options = byFormat[format]

  useEffect(() => {
    api.env().then(setEnv).catch(() => setEnv(null))
    api.workbench.history().then(setHistory).catch(() => setHistory([]))
    api.dss.settings().then(setDss).catch(() => {})
  }, [])

  // In the sandbox a signer is opened right away, so signing is one click from the start.
  useEffect(() => {
    if (environment !== "Sandbox" || !env) return
    if (asText(byFormat.pades.credentialId) || asText(byFormat.cades.credentialId) || asText(byFormat.xades.credentialId)) return
    const signer = env.signers.find((s) => s.id === "rsa-2048" && s.isUsable) ?? env.signers.find((s) => s.isUsable)
    if (!signer) return
    api.credentials.sandbox(signer.id).then((facts) => setByFormat((all) => ({
      pades: asText(all.pades.credentialId) ? all.pades : setPath(all.pades, "credentialId", facts.id),
      cades: asText(all.cades.credentialId) ? all.cades : setPath(all.cades, "credentialId", facts.id),
      xades: asText(all.xades.credentialId) ? all.xades : setPath(all.xades, "credentialId", facts.id),
    }))).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [env, environment, byFormat.pades.credentialId, byFormat.cades.credentialId, byFormat.xades.credentialId])

  // A new environment starts from that environment's defaults: credentials and TSAs differ.
  const firstEnvironment = useRef(environment)
  useEffect(() => {
    if (firstEnvironment.current === environment) return
    firstEnvironment.current = environment
    setByFormat({
      pades: initial(schema, "pades", environment, frameworks),
      cades: initial(schema, "cades", environment, frameworks),
      xades: initial(schema, "xades", environment, frameworks),
    })
    setValidateOptions({ validate: true, validation: initial(schema, "pades", environment, frameworks).validation })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [environment])

  const update = useCallback((change: (current: Options) => Options) => {
    setByFormat((all) => ({ ...all, [format]: change(all[format]) }))
  }, [format])

  const set = useCallback((path: string, value: unknown) => update((o) => setPath(o, path, value)), [update])
  const patch = useCallback((values: Record<string, unknown>) =>
    update((o) => Object.entries(values).reduce((acc, [path, value]) => setPath(acc, path, value), o)), [update])
  const applyPreset = useCallback((preset: SchemaPreset) =>
    update((o) => Object.entries(preset.set).reduce((acc, [path, value]) => (hasPath(acc, path) ? setPath(acc, path, value) : acc), o)), [update])
  const reset = useCallback(() => update(() => initial(schema, format, environment, frameworks)), [update, schema, format, environment, frameworks])

  const setFormat = useCallback((next: Format) => {
    localStorage.setItem("wb.format", JSON.stringify(next))
    setFormatState(next)
    setEvaluation(null)
  }, [])

  const toggleFramework = useCallback((id: string) => {
    setFrameworks((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      localStorage.setItem("wb.frameworks", JSON.stringify([...next]))
      setByFormat((all) => {
        const adjust = (f: Format) => {
          let o = withoutFrameworks(schema, f, all[f], next)
          if (id === "brazil") {
            o = setPath(o, "validation.useBrasil", next.has("brazil"))
            if (asText(getPath(o, "environment")) === "Real") o = setPath(o, "validation.trust", next.has("brazil") ? ["System", "IcpBrasil"] : ["System"])
          }
          return o
        }
        return { pades: adjust("pades"), cades: adjust("cades"), xades: adjust("xades") }
      })
      if (id === "brazil") {
        setValidateOptions((o) => {
          let v = setPath(o, "validation.useBrasil", next.has("brazil"))
          const trust = (getPath(v, "validation.trust") as string[] | undefined) ?? []
          v = setPath(v, "validation.trust", next.has("brazil")
            ? (asText(getPath(v, "validation.environment")) === "Real" && !trust.includes("IcpBrasil") ? [...trust, "IcpBrasil"] : trust)
            : trust.filter((x) => x !== "IcpBrasil"))
          return v
        })
      }
      return next
    })
  }, [schema])

  // Apply the rules whenever the options change (debounced: typing should not flood the server).
  const sequence = useRef(0)
  useEffect(() => {
    const id = ++sequence.current
    setEvaluating(true)
    const timer = setTimeout(() => {
      api.workbench.evaluate(format, options)
        .then((e) => id === sequence.current && setEvaluation(e))
        .catch(() => id === sequence.current && setEvaluation(null))
        .finally(() => id === sequence.current && setEvaluating(false))
    }, 150)
    return () => clearTimeout(timer)
  }, [format, options])

  const state = useCallback((key: string): OptionState => evaluation?.states[key] ?? shown, [evaluation])

  const visibleValues = useCallback((option: SchemaOption) => option.values.filter((v) => {
    if (v.framework && !frameworks.has(v.framework)) return false
    return !option.valueStateKey || state(`${option.valueStateKey}.${v.value}`).visible
  }), [frameworks, state])

  const isVisible = useCallback((option: SchemaOption) => {
    if (!option.formats.includes(format)) return false
    if (option.framework && !frameworks.has(option.framework)) return false
    if (option.support === "notInLibrary") return true
    if (!option.when.every((w) => w.in.includes(asText(getPath(options, w.path))))) return false
    if (option.stateKey && !state(option.stateKey).visible) return false
    return option.kind !== "choice" || visibleValues(option).length > 0
  }, [format, frameworks, options, state, visibleValues])

  // ── Runs ──────────────────────────────────────────────────────────

  const stream = useRef<EventSource | null>(null)
  useEffect(() => () => stream.current?.close(), [])

  /** Starts a run of either kind and follows its event stream into that kind's slot. */
  const startRun = useCallback((kind: RunKind, runFormat: Format | "", runOptions: Options) => new Promise<RunView | null>((resolve) => {
    stream.current?.close()
    patchSlot(kind, () => ({ run: null, logs: [], running: true }))
    const finish = (result: RunView | null) => {
      patchSlot(kind, (slot) => (result ? { run: result, logs: result.logs, running: false } : { ...slot, running: false }))
      api.workbench.history().then(setHistory).catch(() => {})
      resolve(result)
    }
    api.workbench.start(runFormat, runOptions, dss.enabled, kind)
      .then(({ id }) => {
        const source = new EventSource(api.workbench.eventsUrl(id))
        stream.current = source
        source.onmessage = (message) => {
          const event = JSON.parse(message.data) as RunEvent
          if (event.log) patchSlot(kind, (slot) => ({ ...slot, logs: [...slot.logs, event.log!] }))
          if (event.run) {
            source.close()
            finish(event.run)
          }
        }
        source.onerror = () => {
          // The stream dropped: the run keeps going on the server, so fetch its result.
          source.close()
          const poll = () => api.workbench.run(id).then((result) => (result ? finish(result) : void setTimeout(poll, 500))).catch(() => finish(null))
          poll()
        }
      })
      .catch((e: Error) => {
        toast.error(t("wb.run.failedToStart"), { description: e.message })
        finish(null)
      })
  }), [dss.enabled, patchSlot, t])

  const sign = useCallback((overrides?: Options) => startRun("sign", format, overrides ?? options), [startRun, format, options])

  const validate = useCallback((target?: ValidateTarget) => {
    const file = target ?? validateTarget
    if (!file) return Promise.resolve(null)
    return startRun("validate", "", { fileId: file.fileId, dataId: file.dataId ?? null, settings: validateOptions.validation })
  }, [startRun, validateTarget, validateOptions])

  const openInValidate = useCallback((target: ValidateTarget) => {
    setValidateTarget(target)
    setMode("validate")
    void startRun("validate", "", { fileId: target.fileId, dataId: target.dataId ?? null, settings: validateOptions.validation })
  }, [setMode, startRun, validateOptions])

  const openRun = useCallback(async (id: string) => {
    const result = await api.workbench.run(id)
    if (result) {
      patchSlot(result.kind, () => ({ run: result, logs: result.logs, running: false }))
      setMode(result.kind)
    }
  }, [patchSlot, setMode])

  const reuse = useCallback((source: RunView) => {
    setFormat(source.format)
    setByFormat((all) => ({ ...all, [source.format]: withoutFrameworks(schema, source.format, structuredClone(source.options), frameworks) }))
  }, [schema, frameworks, setFormat])

  // ── Variants ──────────────────────────────────────────────────────

  const [variants, setVariants] = useState<Variants | null>(null)
  const [variantsRunning, setVariantsRunning] = useState(false)
  const stopRequested = useRef(false)
  const stopVariants = useCallback(() => { stopRequested.current = true }, [])

  const runVariants = useCallback(async (option: SchemaOption) => {
    if (!option.path) return
    const values = visibleValues(option).filter((v) => v.support === "supported")
    const update = (value: string, change: Partial<VariantRow>) =>
      setVariants((current) => current && { ...current, rows: current.rows.map((r) => (r.value === value ? { ...r, ...change } : r)) })
    stopRequested.current = false
    setVariantsRunning(true)
    setVariants({ option, format, rows: values.map((v) => ({ value: v.value, title: v.title, status: "pending" })) })
    try {
      for (const v of values) {
        if (stopRequested.current) break
        const candidate = setPath(options, option.path, v.value === "" ? null : v.value)
        update(v.value, { status: "running" })
        const rules = await api.workbench.evaluate(format, candidate)
        if (!rules.canSign) {
          update(v.value, { status: "skipped", reason: rules.issues.find((i) => i.severity === "Error")?.message })
          continue
        }
        const { id } = await api.workbench.start(format, candidate, dss.enabled)
        let result: RunView | undefined
        while (!result) {
          await new Promise((resolve) => setTimeout(resolve, 250))
          result = await api.workbench.run(id)
        }
        update(v.value, { status: "done", run: result })
      }
    } catch (e) {
      toast.error(t("wb.run.failedToStart"), { description: (e as Error).message })
    } finally {
      setVariantsRunning(false)
      api.workbench.history().then(setHistory).catch(() => {})
    }
  }, [visibleValues, options, format, dss.enabled, t])

  const saveDss = useCallback(async (settings: DssSettings) => {
    try {
      setDss(await api.dss.save(settings))
      setDssStatus(await api.dss.status())
    } catch (e) {
      toast.error((e as Error).message)
    }
  }, [])
  const checkDss = useCallback(async () => setDssStatus(await api.dss.status()), [])

  const value = useMemo<WorkbenchValue>(() => ({
    mode, setMode, validateTarget, setValidateTarget, validateOptions, setValidateOption, validate, openInValidate,
    schema, env, environment, format, setFormat, frameworks, toggleFramework, options, set, patch, applyPreset, reset,
    evaluation, evaluating, state, credential: evaluation?.credential ?? null, isVisible, visibleValues,
    run, logs, running, sign, history, openRun, reuse, variants, variantsRunning, runVariants, stopVariants, dss, dssStatus, saveDss, checkDss,
  }), [mode, setMode, validateTarget, validateOptions, setValidateOption, validate, openInValidate, variants, variantsRunning, runVariants, stopVariants, schema, env, environment, format, setFormat, frameworks, toggleFramework, options, set, patch, applyPreset, reset,
    evaluation, evaluating, state, isVisible, visibleValues, run, logs, running, sign, history, openRun, reuse, dss, dssStatus, saveDss, checkDss])

  return <Context.Provider value={value}>{children}</Context.Provider>
}

export function useWorkbench() {
  const value = useContext(Context)
  if (!value) throw new Error("useWorkbench outside WorkbenchProvider")
  return value
}
