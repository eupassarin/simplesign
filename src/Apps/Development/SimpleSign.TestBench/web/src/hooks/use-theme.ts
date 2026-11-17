import { useCallback, useEffect, useState } from "react"

export type Theme = "light" | "dark" | "system"

function apply(theme: Theme) {
  const dark = theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches)
  document.documentElement.classList.toggle("dark", dark)
}

/** Light / dark / system, saved in localStorage (index.html applies it before first paint). */
export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => (localStorage.getItem("theme") as Theme | null) ?? "system")
  useEffect(() => {
    apply(theme)
    if (theme !== "system") return
    const media = matchMedia("(prefers-color-scheme: dark)")
    const onChange = () => apply("system")
    media.addEventListener("change", onChange)
    return () => media.removeEventListener("change", onChange)
  }, [theme])
  const setTheme = useCallback((next: Theme) => {
    localStorage.setItem("theme", next)
    setThemeState(next)
  }, [])
  const resolved: "light" | "dark" = theme === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : theme
  return { theme, resolved, setTheme }
}
