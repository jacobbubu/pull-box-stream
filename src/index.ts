import * as pull from 'pull-stream'
import * as sodium from 'chloride'
import Reader from '@jacobbubu/pull-reader'
import through from '@jacobbubu/pull-through'
import split from './split-buffer'
import increment from './increment-buffer'

const isBuffer = Buffer.isBuffer
const concat = Buffer.concat

const box = sodium.crypto_secretbox_easy
const unbox = sodium.crypto_secretbox_open_easy

function unbox_detached(mac: Buffer, boxed: Buffer, nonce: Buffer, key: Buffer) {
  return sodium.crypto_secretbox_open_easy(concat([mac, boxed]), nonce, key)
}

const max = 1024 * 4

const NONCE_LEN = 24
const HEADER_LEN = 2 + 16 + 16

function isZeros(buf: Buffer) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false
  }
  return true
}

function copy(aBuf: Buffer) {
  const bBuf = Buffer.alloc(aBuf.length)
  aBuf.copy(bBuf, 0, 0, aBuf.length)
  return bBuf
}

export function createBoxStream(key: Buffer, initNonce?: Buffer) {
  let _initNonce: Buffer
  if (key.length === 56) {
    _initNonce = key.slice(32, 56)
    key = key.slice(0, 32)
  } else if (!(key.length === 32 && initNonce!.length === 24)) {
    throw new Error('nonce must be 24 bytes')
  } else {
    _initNonce = initNonce!
  }

  // We need two nonces because increment mutates,
  // and we need the next for the header,
  // and the next next nonce for the packet
  const nonce1 = copy(_initNonce)
  const nonce2 = copy(_initNonce)
  const head = Buffer.alloc(18)

  return through(
    function (data: string | Buffer) {
      let _data: Buffer
      if ('string' === typeof data) {
        _data = Buffer.from(data, 'utf8')
      } else if (!isBuffer(data)) {
        return this.emit('error', new Error('must be buffer'))
      } else {
        _data = data
      }

      if (data.length === 0) {
        return
      }

      const input = split(_data, max)

      for (let i = 0; i < input.length; i++) {
        head.writeUInt16BE(input[i].length, 0)
        const boxed = box(input[i], increment(nonce2), key)
        // Write the mac into the header.
        boxed.copy(head, 2, 0, 16)

        this.queue(box(head, nonce1, key))
        this.queue(boxed.slice(16, 16 + input[i].length))

        increment(increment(nonce1))
        increment(nonce2)
      }
    },
    function () {
      // Handle special-case of empty session
      // Final header is same length as header except all zeros (inside box)
      const final = Buffer.alloc(2 + 16)
      final.fill(0)
      this.queue(box(final, nonce1, key))
      this.queue(null)
    }
  )
}

export function createUnboxStream(key: Buffer, nonce?: Buffer) {
  let _nonce: Buffer
  if (key.length === 56) {
    _nonce = key.slice(32, 56)
    key = key.slice(0, 32)
  } else if (!(key.length === 32 && nonce!.length === 24)) {
    throw new Error('nonce must be 24 bytes')
  } else {
    _nonce = copy(nonce!)
  }

  const reader = Reader()
  let ended: pull.EndOrError

  return function (read: pull.Source<Buffer>) {
    reader(read)
    return function (end: pull.Abort, cb: pull.SourceCallback<Buffer>) {
      if (end) {
        return reader.abort(end, cb)
      }
      // Use abort when the input was invalid,
      // but the source hasn't actually ended yet.
      function abort(err: pull.Abort) {
        reader.abort((ended = err || true), cb)
      }

      if (ended) {
        return cb(ended)
      }
      reader.read(HEADER_LEN, function (err, cipherHeader) {
        if (err === true) {
          return cb((ended = new Error('unexpected hangup')))
        }
        if (err) {
          return cb((ended = err))
        }

        const header = unbox(cipherHeader, _nonce, key)

        if (!header) {
          {
            return abort(new Error('invalid header'))
          }
        }

        // Valid end of stream
        if (isZeros(header)) {
          return cb((ended = true))
        }

        const length = header.readUInt16BE(0)
        const mac = header.slice(2, 34)

        reader.read(length, function (err, cipherPacket) {
          if (err) {
            return cb((ended = err))
          }
          // Recreate a valid packet
          // TODO: PR to sodium bindings for detached box/open
          const plainPacket = unbox_detached(mac, cipherPacket, increment(_nonce), key)
          if (!plainPacket) {
            return abort(new Error('invalid packet'))
          }

          increment(_nonce)
          cb(null, plainPacket)
        })
      })
    }
  }
}
