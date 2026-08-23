import crypto from 'crypto'

// disable auto body parsing so we can hash the exact raw bytes
export const config = { api: { bodyParser: false } }

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', chunk => { data += chunk })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

export default async function handler(req, res) {
  if (req.method === 'GET') return res.status(200).send('OK')
  if (req.method !== 'POST') return res.status(405).send('zaml')

  const timestamp = req.headers['x-timestamp']
  const signature = req.headers['x-signature']
  if (!timestamp || !signature) {
    return res.status(400).send('zaml')
  }

  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp))
  if (Number.isNaN(age) || age > 300) {
    return res.status(400).send('zaml')
  }

  const rawBody = await readRawBody(req)
  const signingString = `${timestamp}.${rawBody}`
  const expected = crypto
    .createHmac('sha256', process.env.SECRET_KEY)
    .update(signingString)
    .digest('base64')

  // --- TEMP DEBUG: remove once verified ---
  console.log('SERVER expected:', expected)
  console.log('CLIENT sent    :', signature)
  console.log('signing string :', signingString)
  console.log('secret loaded  :', process.env.SECRET_KEY ? 'yes len=' + process.env.SECRET_KEY.length : 'MISSING')
  // ----------------------------------------

  const a = Buffer.from(expected)
  const b = Buffer.from(signature)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).send('Bad request')
  }

  let parsed
  try {
    parsed = JSON.parse(rawBody)
  } catch {
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
