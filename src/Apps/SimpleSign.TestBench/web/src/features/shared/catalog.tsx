import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { OptionInfo } from "@/lib/types"

const CatalogContext = createContext<Record<string, OptionInfo>>({})

/** Loads the explanations of the options that are not in the workbench schema (signers, TSAs…), in the current language. */
export function CatalogProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n()
  const [catalog, setCatalog] = useState<Record<string, OptionInfo>>({})
  useEffect(() => {
    api.catalog().then(setCatalog).catch(() => setCatalog({}))
  }, [locale])
  return <CatalogContext.Provider value={catalog}>{children}</CatalogContext.Provider>
}

export function useCatalog() {
  return useContext(CatalogContext)
}
