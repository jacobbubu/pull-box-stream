import * as pull from 'pull-stream'
import split from '@jacobbubu/pull-split'
import through from '@jacobbubu/pull-through'
import * as sodium from 'chloride'

const toBeTruthy = (d: any) => !!d

const serialize = function () {
  return through(function (data) {
    this.queue(Buffer.from(JSON.stringify(data) + '\n'))
  })
}

const parse = function () {
  return pull(
    split(),
    pull.filter(toBeTruthy),
    pull.map((data) => JSON.parse(data))
  )
}

function testKey(str: string) {
  return sodium.crypto_hash(Buffer.from(str)).slice(0, 56)
}

export { serialize }
export { parse }
export { testKey }
