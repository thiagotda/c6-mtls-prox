import express from 'express';
import https from 'node:https';
import fetch from 'node-fetch';

const app = express();
app.use(express.json({ limit: '4mb' }));

const TOKEN = process.env.PROXY_TOKEN;

const PERMITIDOS = [
  'cdpj.partners.bancointer.com.br',
  'baas-api.c6bank.info',
  'baas-api-sandbox.c6bank.info',
  'baas-sandbox.c6bank.info',
];

app.get('/', (_req, res) => res.json({ ok: true }));

app.post('/proxy', async (req, res) => {
  if (req.headers.authorization !== `Bearer ${TOKEN}`) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { url, method = 'GET', headers = {}, body, cert, key, passphrase, encoding } = req.body || {};
  if (!url || !cert || !key) {
    return res.status(400).json({ error: 'url, cert e key obrigatorios' });
  }

  let alvo;
  try {
    alvo = new URL(url);
  } catch {
    return res.status(400).json({ error: 'url invalida' });
  }
  if (!PERMITIDOS.includes(alvo.hostname)) {
    return res.status(403).json({ error: `host nao permitido: ${alvo.hostname}` });
  }

  const agent = new https.Agent({
    cert,
    key,
    passphrase: passphrase || undefined,
    keepAlive: true,
  });

  try {
    const r = await fetch(url, { method, headers, body, agent });

    const buf = Buffer.from(await r.arrayBuffer());
    const base64 = encoding === 'base64';

    res.json({
      status: r.status,
      encoding: base64 ? 'base64' : 'text',
      body: base64 ? buf.toString('base64') : buf.toString('utf8'),
    });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

app.listen(process.env.PORT || 10000);
