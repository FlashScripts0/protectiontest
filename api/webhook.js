import crypto from 'crypto'

export const config = { api: { bodyParser: false } }

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', c => { data += c })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

export default async function handler(req, res) {
  if (req.method === 'GET') return res.status(200).send('OK')
  if (req.method !== 'POST') return res.status(405).send('zaml')

  const timestamp = req.headers['x-timestamp']
  const signature = req.headers['x-signature']
  if (!timestamp || !signature) return res.status(400).send('zaml')

  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp))
  if (Number.isNaN(age) || age > 300) return res.status(400).send('zaml')

  const rawBody = await readRawBody(req)

  // verify HMAC over the raw wrapper body (ciphertext)
  const expected = crypto
    .createHmac('sha256', process.env.SECRET_KEY)
    .update(`${timestamp}.${rawBody}`)
    .digest('base64')

  const a = Buffer.from(expected)
  const b = Buffer.from(signature)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).send('Bad request')
  }

  // parse wrapper, then decrypt the embed JSON
  let wrapper
  try { wrapper = JSON.parse(rawBody) } catch { return res.status(400).send('zaml') }

  let parsed
  try {
    const key = Buffer.from(process.env.ENC_KEY)          // 32 chars -> 32 bytes -> AES-256
    const iv = Buffer.from(wrapper.iv, 'base64')
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    let dec = decipher.update(wrapper.data, 'base64', 'utf8')
    dec += decipher.final('utf8')
    parsed = JSON.parse(dec)
  } catch (e) {
    console.error('decrypt failed:', e.message)
    return res.status(400).send('zaml')
  }

  const { embeds, content } = parsed
  if (!embeds) return res.status(400).send('zaml')

  await fetch(process.env.DISCORD_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: content || '', embeds })
  })

  return res.status(200).json({ ok: true })
}
