import { createContext, useContext } from "react"

/** Lets a page send a file to another page (e.g. the signing Result to Validation). */
export interface Navigation {
  validate: (file: { id: string; name: string }) => void
}

export const NavigationContext = createContext<Navigation>({ validate: () => {} })

export function useNavigation() {
  return useContext(NavigationContext)
}
