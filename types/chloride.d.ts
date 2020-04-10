declare module 'chloride' {
  export function crypto_secretbox_open_easy(context: Buffer, nonce: Buffer, key: Buffer): Buffer
  export function randombytes(buf: Buffer): void
  export function crypto_secretbox_easy(data: Buffer, nonce: Buffer, key: Buffer): Buffer
  export function crypto_hash(data: Buffer): Buffer
}
