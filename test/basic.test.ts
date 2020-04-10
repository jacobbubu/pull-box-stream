import * as pull from 'pull-stream'
import * as sodium from 'chloride'
import { randomBytes } from 'crypto'
import * as boxes from '../src'
import split from '@jacobbubu/pull-randomly-split'
import increment from '../src/increment-buffer'
import bitFlipper from '@jacobbubu/pull-bitflipper'

const unbox = sodium.crypto_secretbox_open_easy
const concat = Buffer.concat

function testKey(str: string) {
  return sodium.crypto_hash(Buffer.from(str)).slice(0, 56)
}

function randomBuffers(len: number, n: number) {
  const res: Buffer[] = []
  while (n--) {
    res.push(randomBytes(len))
  }
  return res
}

function rand(i: number) {
  return Math.floor(Math.random() * i)
}

function stall() {
  let _cb: pull.SourceCallback<Buffer>
  return function (abort: pull.Abort, cb: pull.SourceCallback<Buffer>) {
    if (abort) {
      _cb?.(abort)
      cb?.(abort)
    } else {
      _cb = cb
    }
  }
}

describe('basic', () => {
  it('encrypt a stream', (done) => {
    const key = testKey('encrypt a stream - test 1')
    const text = 'hello there'
    pull(
      pull.values([Buffer.from(text)]),
      boxes.createBoxStream(key),
      pull.collect(function (err, ary: Buffer[]) {
        if (err) throw err
        // cipher text

        // decrypt the head.
        const head = ary[0]
        const chunk = ary[1]

        const _key = key.slice(0, 32)
        const _nonce = key.slice(32, 56)

        const plainHead = unbox(head, _nonce, _key)
        const length = plainHead.readUInt16BE(0)

        expect(length).toBe(11)
        expect(length).toBe(chunk.length)

        const mac = plainHead.slice(2, 18)
        const nonce2 = Buffer.alloc(24)
        _nonce.copy(nonce2, 0, 0, 24)

        const plainChunk = unbox(concat([mac, chunk]), increment(nonce2), _key)

        expect(plainChunk.equals(Buffer.from(text))).toBe(true)

        // Now decrypt the same
        pull(
          pull.values(ary),
          boxes.createUnboxStream(key),
          pull.collect(function (err, data: Buffer[]) {
            expect(err).toBeFalsy()
            expect(data[0].equals(Buffer.from(text))).toBe(true)
            done()
          })
        )
      })
    )
  })

  it('encrypt/decrypt simple', (done) => {
    const key = testKey('encrypt/decrypt a stream, easy')

    let input = [Buffer.from('can you read this?'), Buffer.alloc(4100)]
    pull(
      pull.values(input),
      boxes.createBoxStream(Buffer.from(key)),
      boxes.createUnboxStream(Buffer.from(key)),
      pull.collect(function (err, output: Buffer[]) {
        expect(err).toBeFalsy()
        const joinedOutput = concat(output)
        const joinedInput = concat(input)
        expect(joinedOutput.length).toBe(joinedInput.length)
        expect(joinedOutput.equals(joinedInput)).toBe(true)
        done()
      })
    )
  })

  it('encrypt/decrypt', (done) => {
    const input = randomBuffers(1024 * 512, 2 * 10)

    const key = testKey('encrypt/decrypt a stream')

    pull(
      pull.values(input),
      split(),
      boxes.createBoxStream(Buffer.from(key)),
      split(),
      boxes.createUnboxStream(Buffer.from(key)),
      pull.collect(function (err, output) {
        expect(err).toBeFalsy()
        const joinedOutput = concat(output)
        const joinedInput = concat(input)
        expect(joinedOutput.length).toBe(joinedInput.length)
        expect(joinedOutput.equals(joinedInput)).toBe(true)
        done()
      })
    )
  })

  it('error if input is not a buffer', (done) => {
    const key = testKey('error if not a buffer')

    pull(
      pull.values([0, 1, 2], function (_) {
        done()
      }),
      boxes.createBoxStream(key),
      pull.collect(function (err) {
        expect(err).toBeTruthy()
      })
    )
  })

  it('detect flipped bits', (done) => {
    const input = randomBuffers(1024, 100)
    const key = testKey('bit flipper')

    pull(
      pull.values(input, function () {
        done()
      }),
      boxes.createBoxStream(key),
      bitFlipper(0.1),
      boxes.createUnboxStream(key),
      pull.collect(function (err, output) {
        expect(err).toBeTruthy()
        expect(output.length).not.toBe(input.length)
      })
    )
  })

  it('protect against reordering', (done) => {
    const input = randomBuffers(1024, 100)
    const key = testKey('reordering')

    pull(
      pull.values(input),
      boxes.createBoxStream(key),
      pull.collect(function (_, valid) {
        // Randomly switch two blocks
        const invalid = valid.slice()
        // Since every even packet is a header,
        // moving those will produce valid messages
        // but the counters will be wrong.
        const i = rand(valid.length / 2) * 2
        const j = rand(valid.length / 2) * 2
        invalid[i] = valid[j]
        invalid[i + 1] = valid[j + 1]
        invalid[j] = valid[i]
        invalid[j + 1] = valid[i + 1]
        pull(
          pull.values(invalid, function (_) {
            done()
          }),
          boxes.createUnboxStream(key),
          pull.collect(function (err, output) {
            expect(err).toBeTruthy()
            expect(output.length).not.toBe(input.length)
          })
        )
      })
    )
  })

  it('detect unexpected hangup', (done) => {
    const input = [Buffer.from('I <3 TLS\n'), Buffer.from('...\n'), Buffer.from('NOT!!!')]
    const key = testKey('detect unexpected hangup')

    pull(
      pull.values(input),
      boxes.createBoxStream(key),
      pull.take(4), // Header packet header packet.
      boxes.createUnboxStream(key),
      pull.collect(function (err, data: Buffer[]) {
        expect(err).toBeTruthy()
        expect(data.join('')).toBe('I <3 TLS\n...\n')
        done()
      })
    )
  })

  it('detect unexpected hangup, interrupt just the last packet', (done) => {
    const input = [Buffer.from('I <3 TLS\n'), Buffer.from('...\n'), Buffer.from('NOT!!!')]
    const key = testKey('drop hangup packet')

    pull(
      pull.values(input),
      boxes.createBoxStream(key),
      pull.take(6), // Header packet header packet.
      boxes.createUnboxStream(key),
      pull.collect(function (err, data: Buffer[]) {
        expect(err).toBeTruthy()
        expect(data.join('')).toBe('I <3 TLS\n...\nNOT!!!')
        done()
      })
    )
  })

  it('immediately hangup', (done) => {
    const key = testKey('empty session')

    pull(
      pull.values([]),
      boxes.createBoxStream(key),
      boxes.createUnboxStream(key),
      pull.collect(function (err, data: Buffer[]) {
        expect(err).toBeFalsy()
        expect(data).toEqual([])
        done()
      })
    )
  })

  it('stalled abort', (done) => {
    const key = testKey('stalled abort')

    const err = new Error('intentional')
    const read = pull(stall(), boxes.createBoxStream(key))

    let i = 0
    read(null, function (_err) {
      expect(_err).toBe(err)
      expect(++i).toBe(1)
    })

    read(err, function () {
      expect(err).toBeTruthy()
      expect(++i).toBe(2)
      done()
    })
  })

  it('stalled abort2', (done) => {
    const key = testKey('stalled abort2')

    const err = new Error('intentional')
    const read = pull(stall(), boxes.createUnboxStream(key))

    let i = 0
    read(null, function (_err) {
      expect(_err).toBe(err)
      expect(++i).toBe(1)
    })

    read(err, function () {
      expect(err).toBeTruthy()
      expect(++i).toBe(2)
      done()
    })
  })

  it('encrypt empty buffers', (done) => {
    const key = testKey('empty')
    pull(
      pull.values([Buffer.alloc(0)]),
      boxes.createBoxStream(key),
      boxes.createUnboxStream(key),
      pull.collect(function (_, buffers) {
        const actual = Buffer.concat(buffers)
        expect(actual.equals(Buffer.alloc(0)))
        done()
      })
    )
  })
})
