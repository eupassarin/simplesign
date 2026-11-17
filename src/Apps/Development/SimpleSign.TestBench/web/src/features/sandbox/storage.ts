// localStorage is per origin, and the TestBench keeps its own keys too: every key is prefixed,
// and every access tolerates a blocked storage (private window, cleared data).
const prefix = "sbx."

export function load(key: string): string | null {
  try {
    return localStorage.getItem(prefix + key)
  } catch {
    return null
  }
}

export function save(key: string, value: string): void {
  try {
    localStorage.setItem(prefix + key, value)
  } catch {
    // Not kept: the choice lasts until the page is reloaded.
  }
}
