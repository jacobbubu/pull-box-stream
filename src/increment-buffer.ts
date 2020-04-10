export default function incrementBuffer(buf: Buffer) {
  const len = buf.length
  let i

  for (i = len - 1; i >= 0 && buf[i] === 255; i--) {
    buf[i] = 0
  }

  if (i >= 0) {
    buf[i] = buf[i] + 1
  }

  return buf
}
