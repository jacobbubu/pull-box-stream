export default function split(data: Buffer, max: number) {
  if (max <= 0) {
    throw new Error('cannot split into zero (or smaller) length buffers')
  }

  if (data.length <= max) {
    return [data]
  }

  const out = []
  let start = 0

  while (start < data.length) {
    out.push(data.slice(start, Math.min(start + max, data.length)))
    start += max
  }

  return out
}
