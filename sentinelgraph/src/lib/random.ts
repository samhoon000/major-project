export const rand = (a: number, b: number) => a + Math.random() * (b - a)
export const randInt = (a: number, b: number) => Math.floor(rand(a, b + 1))
export const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(Math.random() * xs.length)]
export const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x))
export const chance = (p: number) => Math.random() < p
/** log-uniform sample — network quantities are heavy-tailed */
export const logRand = (a: number, b: number) => Math.exp(rand(Math.log(Math.max(a, 1e-6)), Math.log(Math.max(b, 1e-6))))
export const gauss = () => {
  let u = 0
  let v = 0
  while (u === 0) u = Math.random()
  while (v === 0) v = Math.random()
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v)
}
export function weightedPick<T extends { weight: number }>(xs: readonly T[]): T {
  const total = xs.reduce((s, x) => s + x.weight, 0)
  let r = Math.random() * total
  for (const x of xs) {
    r -= x.weight
    if (r <= 0) return x
  }
  return xs[xs.length - 1]
}
let seq = 0
export const uid = (p = 'f') => `${p}${(++seq).toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`
