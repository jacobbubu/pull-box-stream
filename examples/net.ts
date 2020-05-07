import * as pull from 'pull-stream'
import * as net from 'net'
import { serialize, parse, testKey } from './utils'
import * as boxes from '../src'
const toPull = require('stream-to-pull-stream')

const PORT = 3000

const key = testKey('M01 is rocking!')
net
  .createServer((socket) => {
    const client = toPull.duplex(socket) as pull.Duplex<Buffer, Buffer>
    pull(pull.values(['a', 'b', 'c']), serialize(), boxes.createBoxStream(key), client.sink)

    pull(
      client.source,
      boxes.createUnboxStream(key),
      parse(),
      pull.collect((_, ary) => {
        console.log('server received', ary)
      })
    )
  })
  .listen(PORT)

const rawClient = net.createConnection({ port: PORT }, () => {
  const client = toPull.duplex(rawClient) as pull.Duplex<Buffer, Buffer>
  pull(pull.values([1, 2, 3]), serialize(), boxes.createBoxStream(key), client.sink)
  pull(
    client.source,
    boxes.createUnboxStream(key),
    parse(),
    pull.collect((_, ary) => {
      console.log('client received', ary)
    })
  )
})
