import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { toast } from "sonner"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { pairwise, product } from "./combinations"
import type { CredentialFacts, EnvironmentInfo, OptionState } from "@/lib/types"
import {
  asText, getPath, hasPath, setPath,
  type DssSettings, type DssStatus, type Evaluation, type Format, type Options, type RunEvent, type RunKind, type RunLogEntry, type RunSummary,
  type RunEngine, type RunView, type SchemaOption, type SchemaPreset, type SchemaValue, type WorkbenchSchema,
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

/** The tasks of the top bar: the two run kinds, and the Playbook tab. */
export type AppMode = RunKind | "playbook"

interface WorkbenchValue {
  /** The task on screen: make a signature, validate a file (each keeps its own result), or run a playbook. */
  mode: AppMode
  setMode: (mode: AppMode) => void
  validateTarget: ValidateTarget | null
  setValidateTarget: (target: ValidateTarget | null) => void
  /** The trust and revocation settings of the Validate task, shaped like the options ({ validation: … }). */
  validateOptions: Options
  setValidateOption: (path: string, value: unknown) => void
  /** Changes the Validate task's settings at once (a trust profile sets the profile and the policy together). */
  updateValidate: (change: (current: Options) => Options) => void
  /** Changes the options of every format at once (a trust profile applies to PAdES, CAdES and XAdES alike). */
  updateAll: (change: (current: Options, format: Format) => Options) => void
  validate: (target?: ValidateTarget) => Promise<RunView | null>
  /** Shows a file in the Validate task and validates it. */
  openInValidate: (target: ValidateTarget) => void
  schema: WorkbenchSchema
  /** The connected Sandbox (env.sandbox) and the runtime. */
  env: EnvironmentInfo | null
  setEnv: (env: EnvironmentInfo) => void
  format: Format
  setFormat: (format: Format) => void
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
  /** Whether the option is shown for the current format, conditions and rules. */
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
  variantValues: (option: SchemaOption) => SchemaValue[]
  runVariants: (options: SchemaOption[], strategy: Strategy) => Promise<void>
  stopVariants: () => void
  /** Opens a sandbox signer and makes it the signer of the three formats. */
  signWithSandbox: (id: string) => Promise<void>
  /** How a signing run makes the signature: the library or the simplesign CLI (remembered in this browser). */
  engine: RunEngine
  setEngine: (engine: RunEngine) => void
  // DSS
  dss: DssSettings
  dssStatus: DssStatus | null
  saveDss: (settings: DssSettings) => Promise<void>
  checkDss: () => Promise<void>
}

export interface VariantRow {
  key: string
  /** One value per varied option, in the order of <see cref="Variants.options"/>. */
  values: string[]
  titles: string[]
  status: "pending" | "running" | "done" | "skipped"
  /** Why the combination was not run (the rules refuse it). */
  reason?: string
  run?: RunView
}

export type Strategy = "all" | "pairs"

export interface Variants {
  options: SchemaOption[]
  format: Format
  strategy: Strategy
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

/** The defaults of a format: the server's, with a public TSA when no Sandbox is connected. */
function initial(schema: WorkbenchSchema, format: Format, sandboxConnected: boolean): Options {
  let options: Options = structuredClone(schema.defaults[format])
  if (!sandboxConnected) {
    for (const path of ["timestamp.provider", "archiveTimestamp.provider"]) {
      if (hasPath(options, path)) options = setPath(options, path, "DigiCert")
    }
  }
  return options
}

export function WorkbenchProvider({ schema, initialEnv, children }: { schema: WorkbenchSchema; initialEnv: EnvironmentInfo | null; children: ReactNode }) {
  const { t } = useI18n()
  const [env, setEnv] = useState<EnvironmentInfo | null>(initialEnv)
  const connected = !!initialEnv?.sandbox
  const [format, setFormatState] = useState<Format>(() => load<Format>("wb.format", "pades"))
  const [byFormat, setByFormat] = useState<Record<Format, Options>>(() => ({
    pades: initial(schema, "pades", connected),
    cades: initial(schema, "cades", connected),
    xades: initial(schema, "xades", connected),
  }))
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const [mode, setModeState] = useState<AppMode>(() => {
    const saved = load<string>("wb.mode", "sign")
    return saved === "validate" || saved === "playbook" ? saved : "sign"
  })
  const [slots, setSlots] = useState<Record<RunKind, Slot>>({ sign: emptySlot, validate: emptySlot })
  const patchSlot = useCallback((kind: RunKind, change: (slot: Slot) => Slot) => setSlots((all) => ({ ...all, [kind]: change(all[kind]) })), [])
  const { run, logs, running } = slots[mode === "playbook" ? "sign" : mode]
  const [validateTarget, setValidateTarget] = useState<ValidateTarget | null>(null)
  const [validateOptions, setValidateOptions] = useState<Options>(() => ({ validate: true, validation: initial(schema, "pades", connected).validation }))
  const setMode = useCallback((next: AppMode) => {
    localStorage.setItem("wb.mode", JSON.stringify(next))
    setModeState(next)
  }, [])
  const setValidateOption = useCallback((path: string, value: unknown) => setValidateOptions((o) => setPath(o, path, value)), [])
  const updateValidate = useCallback((change: (current: Options) => Options) => setValidateOptions(change), [])
  const updateAll = useCallback((change: (current: Options, format: Format) => Options) =>
    setByFormat((all) => ({ pades: change(all.pades, "pades"), cades: change(all.cades, "cades"), xades: change(all.xades, "xades") })), [])
  const [history, setHistory] = useState<RunSummary[]>([])
  const [engine, setEngineState] = useState<RunEngine>(() => load<RunEngine>("wb.engine", "library") === "cli" ? "cli" : "library")
  const setEngine = useCallback((next: RunEngine) => {
    setEngineState(next)
    try { localStorage.setItem("wb.engine", JSON.stringify(next)) } catch { /* private window: not remembered */ }
  }, [])
  const [dss, setDss] = useState<DssSettings>({ enabled: false, url: "http://localhost:8080" })
  const [dssStatus, setDssStatus] = useState<DssStatus | null>(null)
  const options = byFormat[format]

  useEffect(() => {
    api.workbench.history().then(setHistory).catch(() => setHistory([]))
    api.dss.settings().then(setDss).catch(() => {})
  }, [])

  // With a Sandbox connected a signer is opened right away, so signing is one click from the start.
  useEffect(() => {
    const signers = env?.sandbox?.signers
    if (!signers) return
    if (asText(byFormat.pades.credentialId) || asText(byFormat.cades.credentialId) || asText(byFormat.xades.credentialId)) return
    const signer = signers.find((s) => s.id === "rsa-2048" && s.isUsable) ?? signers.find((s) => s.isUsable)
    if (!signer) return
    api.credentials.sandbox(signer.id).then((facts) => setByFormat((all) => ({
      pades: asText(all.pades.credentialId) ? all.pades : setPath(all.pades, "credentialId", facts.id),
      cades: asText(all.cades.credentialId) ? all.cades : setPath(all.cades, "credentialId", facts.id),
      xades: asText(all.xades.credentialId) ? all.xades : setPath(all.xades, "credentialId", facts.id),
    }))).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [env, byFormat.pades.credentialId, byFormat.cades.credentialId, byFormat.xades.credentialId])

  const update = useCallback((change: (current: Options) => Options) => {
    setByFormat((all) => ({ ...all, [format]: change(all[format]) }))
  }, [format])

  const set = useCallback((path: string, value: unknown) => update((o) => setPath(o, path, value)), [update])
  const patch = useCallback((values: Record<string, unknown>) =>
    update((o) => Object.entries(values).reduce((acc, [path, value]) => setPath(acc, path, value), o)), [update])
  const applyPreset = useCallback((preset: SchemaPreset) =>
    update((o) => Object.entries(preset.set).reduce((acc, [path, value]) => (hasPath(acc, path) ? setPath(acc, path, value) : acc), o)), [update])
  const reset = useCallback(() => update(() => initial(schema, format, !!env?.sandbox)), [update, schema, format, env])

  const setFormat = useCallback((next: Format) => {
    localStorage.setItem("wb.format", JSON.stringify(next))
    setFormatState(next)
    setEvaluation(null)
  }, [])

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
    return !option.valueStateKey || state(`${option.valueStateKey}.${v.value}`).visible
  }), [state])

  const isVisible = useCallback((option: SchemaOption) => {
    if (!option.formats.includes(format)) return false
    if (option.support === "notInLibrary") return true
    if (!option.when.every((w) => w.in.includes(asText(getPath(options, w.path))))) return false
    if (option.stateKey && !state(option.stateKey).visible) return false
    return option.kind !== "choice" || visibleValues(option).length > 0
  }, [format, options, state, visibleValues])

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
    api.workbench.start(runFormat, runOptions, dss.enabled, kind, engine)
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
  }), [dss.enabled, engine, patchSlot, t])

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
    setByFormat((all) => ({ ...all, [source.format]: structuredClone(source.options) }))
  }, [setFormat])

  // ── Variants ──────────────────────────────────────────────────────

  const [variants, setVariants] = useState<Variants | null>(null)
  const [variantsRunning, setVariantsRunning] = useState(false)
  const stopRequested = useRef(false)
  const stopVariants = useCallback(() => { stopRequested.current = true }, [])

  /** The values of an option that can be combined now. */
  const variantValues = useCallback((option: SchemaOption) => visibleValues(option).filter((v) =>
    // A value the rules already lock (SHA-3 on a runtime without it) is not worth a run.
    v.support === "supported" && !(option.valueStateKey && state(`${option.valueStateKey}.${v.value}`).disabled)), [visibleValues, state])

  const runVariants = useCallback(async (varied: SchemaOption[], strategy: Strategy) => {
    const chosen = varied.filter((o) => o.path)
    if (chosen.length === 0) return
    const lists = chosen.map((o) => variantValues(o))
    const combos = (strategy === "pairs" ? pairwise : product)(lists.map((l) => l.map((v) => v.value)))
    const rows: VariantRow[] = combos.map((values) => ({
      key: values.join("\u0000"),
      values,
      titles: values.map((value, i) => lists[i].find((v) => v.value === value)?.title ?? value),
      status: "pending",
    }))
    const update = (key: string, change: Partial<VariantRow>) =>
      setVariants((current) => current && { ...current, rows: current.rows.map((r) => (r.key === key ? { ...r, ...change } : r)) })
    stopRequested.current = false
    setVariantsRunning(true)
    setVariants({ options: chosen, format, strategy, rows })
    try {
      for (const row of rows) {
        if (stopRequested.current) break
        const candidate = chosen.reduce((acc, option, i) => setPath(acc, option.path!, row.values[i] === "" ? null : row.values[i]), options)
        update(row.key, { status: "running" })
        const rules = await api.workbench.evaluate(format, candidate)
        if (!rules.canSign) {
          update(row.key, { status: "skipped", reason: rules.issues.find((i) => i.severity === "Error")?.message })
          continue
        }
        const { id } = await api.workbench.start(format, candidate, dss.enabled, "sign", engine)
        let result: RunView | undefined
        while (!result) {
          await new Promise((resolve) => setTimeout(resolve, 250))
          result = await api.workbench.run(id)
        }
        update(row.key, { status: "done", run: result })
      }
    } catch (e) {
      toast.error(t("wb.run.failedToStart"), { description: (e as Error).message })
    } finally {
      setVariantsRunning(false)
      api.workbench.history().then(setHistory).catch(() => {})
    }
  }, [variantValues, options, format, dss.enabled, engine, t])

  const signWithSandbox = useCallback(async (id: string) => {
    try {
      const facts = await api.credentials.sandbox(id)
      setByFormat((all) => ({
        pades: setPath(all.pades, "credentialId", facts.id),
        cades: setPath(all.cades, "credentialId", facts.id),
        xades: setPath(all.xades, "credentialId", facts.id),
      }))
      toast.success(t("signer.ready"), { description: `${facts.holder} · ${facts.source}` })
    } catch (e) {
      toast.error((e as Error).message)
    }
  }, [t])

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
    signWithSandbox, mode, setMode, validateTarget, setValidateTarget, validateOptions, setValidateOption, updateValidate, updateAll, validate, openInValidate,
    schema, env, setEnv, format, setFormat, options, set, patch, applyPreset, reset,
    evaluation, evaluating, state, credential: evaluation?.credential ?? null, isVisible, visibleValues,
    run, logs, running, sign, history, openRun, reuse, variants, variantsRunning, variantValues, runVariants, stopVariants, engine, setEngine, dss, dssStatus, saveDss, checkDss,
  }), [variantValues, signWithSandbox, mode, setMode, validateTarget, validateOptions, setValidateOption, updateValidate, updateAll, validate, openInValidate, variants, variantsRunning, runVariants, stopVariants, schema, env, setEnv, format, setFormat, options, set, patch, applyPreset, reset,
    evaluation, evaluating, state, isVisible, visibleValues, run, logs, running, sign, history, openRun, reuse, engine, setEngine, dss, dssStatus, saveDss, checkDss])

  return <Context.Provider value={value}>{children}</Context.Provider>
}

export function useWorkbench() {
  const value = useContext(Context)
  if (!value) throw new Error("useWorkbench outside WorkbenchProvider")
  return value
}
