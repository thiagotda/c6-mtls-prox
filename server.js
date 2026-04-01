const https = require("https");
const http = require("http");
const { URLSearchParams } = require("url");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.PROXY_SECRET || "";

// ─── Helper: faz request mTLS ─────────────────────────────────────────────────
function c6Request({ host, path, method, body, contentType, token, certPem, keyPem }) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: host,
      port: 443,
      path,
      method,
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: true,
      headers: {
        "Accept": "application/json",
        "Content-Type": contentType || "application/json",
        ...(token ? { "Authorization": `Bearer ${token}` } : {}),
        ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}),
      },
    };

    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ─── Server ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-proxy-secret");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  if (req.method !== "POST")    { res.writeHead(405); res.end("Method not allowed"); return; }

  // Verificar secret (proteção básica)
  if (SECRET && req.headers["x-proxy-secret"] !== SECRET) {
    res.writeHead(401); res.end(JSON.stringify({ error: "Unauthorized" })); return;
  }

  let payload;
  try {
    const raw = await new Promise((resolve, reject) => {
      let body = "";
      req.on("data", c => body += c);
      req.on("end", () => resolve(body));
      req.on("error", reject);
    });
    payload = JSON.parse(raw);
  } catch {
    res.writeHead(400); res.end(JSON.stringify({ error: "Invalid JSON" })); return;
  }

  const { action, certPem, keyPem, clientId, clientSecret, sandbox, token, data: bodyData } = payload;
  const C6_HOST = sandbox ? "baas-api-sandbox.c6bank.info" : "baas-api.c6bank.info";

  try {
    // ── Auth ──────────────────────────────────────────────────────────────────
    if (action === "auth") {
      const body = new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret }).toString();
      const r = await c6Request({ host: C6_HOST, path: "/v1/auth/", method: "POST", body, contentType: "application/x-www-form-urlencoded", certPem, keyPem });
      res.writeHead(r.status, { "Content-Type": "application/json" });
      res.end(r.body);
      return;
    }

    // ── Emitir boleto ─────────────────────────────────────────────────────────
    if (action === "emitirBoleto") {
      const body = JSON.stringify(bodyData);
      const r = await c6Request({ host: C6_HOST, path: "/v1/bankslip/", method: "POST", body, token, certPem, keyPem });
      res.writeHead(r.status, { "Content-Type": "application/json" });
      res.end(r.body);
      return;
    }

    // ── Consultar boleto ──────────────────────────────────────────────────────
    if (action === "consultarBoleto") {
      const r = await c6Request({ host: C6_HOST, path: `/v1/bankslip/${bodyData.boletoId}`, method: "GET", token, certPem, keyPem });
      res.writeHead(r.status, { "Content-Type": "application/json" });
      res.end(r.body);
      return;
    }

    // ── Cancelar boleto ───────────────────────────────────────────────────────
    if (action === "cancelarBoleto") {
      const r = await c6Request({ host: C6_HOST, path: `/v1/bankslip/${bodyData.boletoId}/cancel`, method: "POST", body: "{}", token, certPem, keyPem });
      res.writeHead(r.status, { "Content-Type": "application/json" });
      res.end(r.body);
      return;
    }

    // ── PIX ───────────────────────────────────────────────────────────────────
    if (action === "enviarPix") {
      const body = JSON.stringify(bodyData);
      const r = await c6Request({ host: C6_HOST, path: "/v1/schedule-payments/pix", method: "POST", body, token, certPem, keyPem });
      res.writeHead(r.status, { "Content-Type": "application/json" });
      res.end(r.body);
      return;
    }

    // ── Health ────────────────────────────────────────────────────────────────
    if (action === "health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, ts: new Date().toISOString() }));
      return;
    }

    res.writeHead(400); res.end(JSON.stringify({ error: `Ação desconhecida: ${action}` }));
  } catch (e) {
    console.error("Erro proxy:", e.message);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(PORT, () => console.log(`C6 mTLS Proxy rodando na porta ${PORT}`));
