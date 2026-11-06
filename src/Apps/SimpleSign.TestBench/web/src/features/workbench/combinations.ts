// Combinations of option values: every one (the product), or a small set in which every pair
// of values of two different options still appears together at least once (pairwise).

/** Every combination: one value of each list. */
export function product(lists: string[][]): string[][] {
  return lists.reduce<string[][]>((rows, list) => rows.flatMap((row) => list.map((value) => [...row, value])), [[]])
}

/**
 * A pairwise covering set, built greedily: each row starts from a pair not yet covered and fills
 * the other positions with the values that cover the most remaining pairs. Deterministic.
 */
export function pairwise(lists: string[][]): string[][] {
  if (lists.length <= 2) return product(lists)
  const key = (i: number, a: string, j: number, b: string) => `${i}\u0000${a}\u0001${j}\u0000${b}`
  const open = new Set<string>()
  for (let i = 0; i < lists.length; i++) {
    for (let j = i + 1; j < lists.length; j++) {
      for (const a of lists[i]) for (const b of lists[j]) open.add(key(i, a, j, b))
    }
  }
  const rows: string[][] = []
  while (open.size > 0) {
    const first = open.values().next().value as string
    const [left, right] = first.split("\u0001")
    const [i, a] = left.split("\u0000")
    const [j, b] = right.split("\u0000")
    const row: (string | undefined)[] = lists.map(() => undefined)
    row[Number(i)] = a
    row[Number(j)] = b
    for (let d = 0; d < lists.length; d++) {
      if (row[d] !== undefined) continue
      let best = lists[d][0]
      let bestGain = -1
      for (const candidate of lists[d]) {
        let gain = 0
        for (let other = 0; other < lists.length; other++) {
          const value = row[other]
          if (value === undefined || other === d) continue
          if (open.has(other < d ? key(other, value, d, candidate) : key(d, candidate, other, value))) gain++
        }
        if (gain > bestGain) {
          best = candidate
          bestGain = gain
        }
      }
      row[d] = best
    }
    const full = row as string[]
    for (let x = 0; x < full.length; x++) for (let y = x + 1; y < full.length; y++) open.delete(key(x, full[x], y, full[y]))
    rows.push(full)
  }
  return rows
}
