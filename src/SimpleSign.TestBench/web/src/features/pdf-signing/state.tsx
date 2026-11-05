import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { api } from "@/lib/api"
import type {
  CredentialFacts,
  DocumentFacts,
  EnvironmentInfo,
  EnvironmentMode,
  OptionInfo,
  OptionState,
  OptionsReport,
  SigningOptions,
} from "@/lib/types"

export function defaultOptions(environment: EnvironmentMode): SigningOptions {
  const tsa = { provider: environment === "Sandbox" ? "Sandbox" : "DigiCert", auth: "None" } as const
  return {
    environment,
    kind: "Baseline",
    level: "BB",
    icpPolicy: "AdRb",
    icpVersionOid: null,
    icpAdRbTimestamp: false,
    customPolicy: { oid: "2.16.76.1.7.1.11.1.3", hashAlgorithm: "Sha256", hashHex: "", uri: "" },
    timestamp: { ...tsa },
    separateArchiveTsa: false,
    archiveTimestamp: { ...tsa },
    returnLowerLevel: false,
    hash: "Sha256",
    padding: "Pkcs1",
    subFilter: "EtsiCadesDetached",
    contentsReservedBytes: null,
    preservePdfA: false,
    fieldMode: "New",
    fieldName: "Signature1",
    existingFieldName: null,
    appearance: {
      visible: false,
      autoPosition: false,
      page: 1,
      x: 72,
      y: 72,
      width: 220,
      height: 70,
      textAlignment: "Left",
      verticalAlignment: "Top",
      shrinkToFit: true,
      maxTextLength: 200,
      showDate: true,
      showReason: false,
      showLocation: false,
      extraLines: [],
      borderWidth: 0.5,
      baseFont: "Helvetica",
      imageFit: "Contain",
    },
    reason: "",
    location: "",
    contactInfo: "",
    signerName: "",
    signingTime: null,
    useSignerDetails: false,
    signerDetails: "Metadata",
    metadata: { commitmentType: "ProofOfApproval" },
    aea: { signerName: "", cpf: "", authMethod: "GovBr", commitmentType: "ProofOfApproval" },
    health: { enabled: false, type: "Prescricao", professionals: [] },
    certification: "None",
    documentInfo: [],
    operationId: "",
    mode: "Sign",
    batchCopies: 5,
    maxConcurrency: 4,
    validate: true,
  }
}

interface SigningContextValue {
  options: SigningOptions
  update: (patch: Partial<SigningOptions> | ((o: SigningOptions) => Partial<SigningOptions>)) => void
  reset: () => void
  report: OptionsReport | null
  document: DocumentFacts | null
  credential: CredentialFacts | null
  catalog: Record<string, OptionInfo>
  env: EnvironmentInfo | null
  environment: EnvironmentMode
  /** State of an option key; unknown keys are visible and enabled. */
  state: (key: string) => OptionState
  evaluating: boolean
}

const SigningContext = createContext<SigningContextValue | null>(null)

export function SigningProvider({ environment, children }: { environment: EnvironmentMode; children: ReactNode }) {
  const [options, setOptions] = useState<SigningOptions>(() => defaultOptions(environment))
  const [report, setReport] = useState<OptionsReport | null>(null)
  const [document, setDocument] = useState<DocumentFacts | null>(null)
  const [credential, setCredential] = useState<CredentialFacts | null>(null)
  const [catalog, setCatalog] = useState<Record<string, OptionInfo>>({})
  const [env, setEnv] = useState<EnvironmentInfo | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const sequence = useRef(0)

  useEffect(() => {
    api.catalog().then(setCatalog).catch(() => {})
    api.env().then(setEnv).catch(() => {})
  }, [])

  // Switching Sandbox / Real starts over: credentials and services differ.
  useEffect(() => {
    setOptions((o) => ({ ...defaultOptions(environment), documentId: o.documentId }))
    setCredential(null)
  }, [environment])

  // Every change is evaluated by the server's Compatibility rules (debounced).
  useEffect(() => {
    const id = ++sequence.current
    setEvaluating(true)
    const timer = setTimeout(() => {
      api
        .options(options)
        .then((response) => {
          if (id !== sequence.current) return
          setReport(response.report)
          setDocument(response.document ?? null)
          setCredential(response.credential ?? null)
        })
        .catch(() => {})
        .finally(() => id === sequence.current && setEvaluating(false))
    }, 120)
    return () => clearTimeout(timer)
  }, [options])

  const update = useCallback<SigningContextValue["update"]>((patch) => {
    setOptions((o) => ({ ...o, ...(typeof patch === "function" ? patch(o) : patch) }))
  }, [])
  const reset = useCallback(() => setOptions(defaultOptions(environment)), [environment])
  const state = useCallback((key: string): OptionState => report?.options[key] ?? { visible: true }, [report])

  const value = useMemo(
    () => ({ options, update, reset, report, document, credential, catalog, env, environment, state, evaluating }),
    [options, update, reset, report, document, credential, catalog, env, environment, state, evaluating],
  )
  return <SigningContext.Provider value={value}>{children}</SigningContext.Provider>
}

export function useSigning() {
  const context = useContext(SigningContext)
  if (!context) throw new Error("useSigning outside SigningProvider")
  return context
}
