const https = require("https");
const http = require("http");
const { URLSearchParams } = require("url");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.PROXY_SECRET || "";
const TOKEN = process.env.PROXY_TOKEN || "";

const PERMITIDOS = [
  "cdpj.partners.bancointer.com.br",
  "cdpj-sandbox.partners.uatinter.co",
  "baas-api.c6bank.info",
  "baas-api-sandbox.c6bank.info",
  "baas-sandbox.c6bank.info",
];

function mtlsRequest({ host, path, method, body, contentType, token, certPem, keyPem, extraHeaders = {}, binary = false, rawHeaders }) {
  return new Promise((resolve, reject) => {
    const headers = rawHeaders
      ? { ...rawHeaders, ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}) }
      : {
          Accept: binary ? "*/*" : "application/json",
          "Content-Type": contentType || "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}),
          ...extraHeaders,
        };

    const req = https.request(
      { hostname: host, port: 443, path, method, cert: certPem, key: keyPem, rejectUnauthorized: true, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on("end", () => {
          const rawBody = Buffer.concat(chunks);
          resolve({ status: res.statusCode, body: rawBody.toString(), rawBody, headers: res.headers });
        });
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function lerJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-proxy-secret");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  if (req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true })); return;
  }

  if (req.method !== "POST") { res.writeHead(405); res.end("Method not allowed"); return; }

  let payload;
  try {
    payload = JSON.parse(await lerJson(req));
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid JSON" })); return;
  }

  // ── Rota genérica /proxy usada pelo app (Bearer BANK_PROXY_TOKEN) ──────────
  if (req.url === "/proxy" || (!payload.action && payload.url)) {
    if (TOKEN && req.headers.authorization !== `Bearer ${TOKEN}`) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" })); return;
    }

    const { url, method = "GET", headers = {}, body, cert, key, passphrase, encoding } = payload;
    if (!url || !cert || !key) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "url, cert e key obrigatorios" })); return;
    }

    let alvo;
    try { alvo = new URL(url); } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "url invalida" })); return;
    }
    if (!PERMITIDOS.includes(alvo.hostname)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `host nao permitido: ${alvo.hostname}` })); return;
    }

    try {
      const r = await mtlsRequest({
        host: alvo.hostname,
        path: alvo.pathname + alvo.search,
        method,
        body,
        certPem: cert,
        keyPem: key,
        rawHeaders: headers,
      });
      const base64 = encoding === "base64";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: r.status,
        encoding: base64 ? "base64" : "text",
        body: base64 ? r.rawBody.toString("base64") : r.rawBody.toString("utf8"),
      }));
    } catch (e) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(e.message || e) }));
    }
    return;
  }

  if (SECRET && req.headers["x-proxy-secret"] !== SECRET) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" })); return;
  }

  const { action } = payload;

  // ═══════════════ C6 BANK (ações antigas) ═══════════════
  const C6_ACTIONS = ["auth", "emitirBoleto", "consultarBoleto", "cancelarBoleto", "enviarPix", "health"];

  if (C6_ACTIONS.includes(action)) {
    const { certPem, keyPem, clientId, clientSecret, sandbox, token, data: bodyData } = payload;
    const C6_HOST = sandbox ? "baas-api-sandbox.c6bank.info" : "baas-api.c6bank.info";

    try {
      if (action === "health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, ts: new Date().toISOString(), proxy: "c6+inter mTLS" })); return;
      }

      if (action === "auth") {
        const body = new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret }).toString();
        const r = await mtlsRequest({ host: C6_HOST, path: "/v1/auth/", method: "POST", body, contentType: "application/x-www-form-urlencoded", certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body); return;
      }

      if (action === "emitirBoleto") {
        const r = await mtlsRequest({ host: C6_HOST, path: "/v1/bank_slips/", method: "POST", body: JSON.stringify(bodyData), token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body); return;
      }

      if (action === "consultarBoleto") {
        const r = await mtlsRequest({ host: C6_HOST, path: `/v1/bank_slips/${bodyData.boletoId}`, method: "GET", token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body); return;
      }

      if (action === "cancelarBoleto") {
        const r = await mtlsRequest({ host: C6_HOST, path: `/v1/bank_slips/${bodyData.boletoId}/cancel`, method: "PUT", token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body || "{}"); return;
      }

      if (action === "enviarPix") {
        const r = await mtlsRequest({ host: C6_HOST, path: "/v1/schedule-payments/pix", method: "POST", body: JSON.stringify(bodyData), token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body); return;
      }
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message })); return;
    }
  }

  // ═══════════════ BANCO INTER (ações antigas) ═══════════════
  if (action === "inter_auth" || action === "inter_request" || action === "inter_request_pdf") {
    const { certPem, keyPem, clientId, clientSecret, scope, sandbox, token, method, path, body: reqBody, conta } = payload;
    const INTER_HOST = sandbox ? "cdpj-sandbox.partners.uatinter.co" : "cdpj.partners.bancointer.com.br";

    try {
      if (action === "inter_auth") {
        const formBody = new URLSearchParams({
          grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret, scope: scope || "extrato.read",
        }).toString();
        const r = await mtlsRequest({ host: INTER_HOST, path: "/oauth/v2/token", method: "POST", body: formBody, contentType: "application/x-www-form-urlencoded", certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body); return;
      }

      if (action === "inter_request_pdf") {
        const extraHeaders = {};
        if (conta) extraHeaders["x-conta-corrente"] = conta;
        const r = await mtlsRequest({ host: INTER_HOST, path, method: "GET", token, certPem, keyPem, extraHeaders, binary: true });
        if (r.status !== 200) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Inter PDF status " + r.status + ": " + r.body.slice(0, 300), status: r.status })); return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          pdf_base64: r.rawBody.toString("base64"),
          status: r.status,
          content_type: r.headers["content-type"] || "",
          size: r.rawBody.length,
        }));
        return;
      }

      if (action === "inter_request") {
        const extraHeaders = {};
        if (conta) extraHeaders["x-conta-corrente"] = conta;
        const r = await mtlsRequest({ host: INTER_HOST, path, method: method || "GET", body: reqBody ? JSON.stringify(reqBody) : undefined, token, certPem, keyPem, extraHeaders });
        res.writeHead(r.status, { "Content-Type": "application/json" }); res.end(r.body); return;
      }
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message })); return;
    }
  }

  res.writeHead(400, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: `Ação desconhecida: ${action}` }));
});

server.listen(PORT, () => console.log(`mTLS Proxy (C6 + Inter) rodando na porta ${PORT}`));
