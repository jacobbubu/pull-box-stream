export function isZeros(buf: Buffer) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) {
      return false
    }
  }
  return true
}

export function copy(aBuf: Buffer) {
  const bBuf = Buffer.alloc(aBuf.length)
  aBuf.copy(bBuf, 0, 0, aBuf.length)
  return bBuf
}
