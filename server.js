const https = require("https");
const http  = require("http");
const { URLSearchParams } = require("url");

const PORT   = process.env.PORT   || 3000;
const SECRET = process.env.PROXY_SECRET || "";

// ─── Helper: faz request mTLS genérico ───────────────────────────────────────
function mtlsRequest({ host, path, method, body, contentType, token, certPem, keyPem, extraHeaders = {} }) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: host,
      port: 443,
      path,
      method,
      cert: certPem,
      key:  keyPem,
      rejectUnauthorized: true,
      headers: {
        "Accept":       "application/json",
        "Content-Type": contentType || "application/json",
        ...(token ? { "Authorization": `Bearer ${token}` } : {}),
        ...(body  ? { "Content-Length": Buffer.byteLength(body) } : {}),
        ...extraHeaders,
      },
    };

    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data",  chunk => data += chunk);
      res.on("end",   ()    => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ─── Server ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-proxy-secret");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  if (req.method !== "POST")    { res.writeHead(405); res.end("Method not allowed"); return; }

  if (SECRET && req.headers["x-proxy-secret"] !== SECRET) {
    res.writeHead(401); res.end(JSON.stringify({ error: "Unauthorized" })); return;
  }

  let payload;
  try {
    const raw = await new Promise((resolve, reject) => {
      let body = "";
      req.on("data",  c => body += c);
      req.on("end",   ()  => resolve(body));
      req.on("error", reject);
    });
    payload = JSON.parse(raw);
  } catch {
    res.writeHead(400); res.end(JSON.stringify({ error: "Invalid JSON" })); return;
  }

  const { action } = payload;

  // ═══════════════════════════════════════════════════════════════════════════
  //  C6 BANK
  // ═══════════════════════════════════════════════════════════════════════════
  const C6_ACTIONS = ["auth", "emitirBoleto", "consultarBoleto", "cancelarBoleto", "enviarPix", "health"];

  if (C6_ACTIONS.includes(action) || action === "health") {
    const { certPem, keyPem, clientId, clientSecret, sandbox, token, data: bodyData } = payload;
    const C6_HOST = sandbox ? "baas-api-sandbox.c6bank.info" : "baas-api.c6bank.info";

    try {
      if (action === "health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, ts: new Date().toISOString(), proxy: "c6+inter mTLS" }));
        return;
      }

      if (action === "auth") {
        const body = new URLSearchParams({
          grant_type:    "client_credentials",
          client_id:     clientId,
          client_secret: clientSecret,
        }).toString();
        const r = await mtlsRequest({ host: C6_HOST, path: "/v1/auth/", method: "POST", body, contentType: "application/x-www-form-urlencoded", certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

      if (action === "emitirBoleto") {
        const r = await mtlsRequest({ host: C6_HOST, path: "/v1/bankslip/", method: "POST", body: JSON.stringify(bodyData), token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

      if (action === "consultarBoleto") {
        const r = await mtlsRequest({ host: C6_HOST, path: `/v1/bankslip/${bodyData.boletoId}`, method: "GET", token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

      if (action === "cancelarBoleto") {
        const r = await mtlsRequest({ host: C6_HOST, path: `/v1/bankslip/${bodyData.boletoId}/cancel`, method: "POST", body: "{}", token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

      if (action === "enviarPix") {
        const r = await mtlsRequest({ host: C6_HOST, path: "/v1/schedule-payments/pix", method: "POST", body: JSON.stringify(bodyData), token, certPem, keyPem });
        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

    } catch (e) {
      console.error("C6 Proxy erro:", e.message);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message })); return;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  BANCO INTER
  // ═══════════════════════════════════════════════════════════════════════════
  if (action === "inter_auth" || action === "inter_request") {
    const { certPem, keyPem, clientId, clientSecret, scope, sandbox, token, method, path, body: reqBody, conta } = payload;
    const INTER_HOST = sandbox
      ? "cdpj-sandbox.partners.uatinter.co"
      : "cdpj.partners.bancointer.com.br";

    try {
      // ── Auth Inter OAuth2 client_credentials ───────────────────────────────
      if (action === "inter_auth") {
        const formBody = new URLSearchParams({
          grant_type:    "client_credentials",
          client_id:     clientId,
          client_secret: clientSecret,
          scope:         scope || "extrato.read",
        }).toString();

        const r = await mtlsRequest({
          host:        INTER_HOST,
          path:        "/oauth/v2/token",
          method:      "POST",
          body:        formBody,
          contentType: "application/x-www-form-urlencoded",
          certPem,
          keyPem,
        });

        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

      // ── Chamada autenticada Inter ──────────────────────────────────────────
      if (action === "inter_request") {
        const extraHeaders: Record<string, string> = {};
        if (conta) extraHeaders["x-conta-corrente"] = conta;

        const bodyStr = reqBody ? JSON.stringify(reqBody) : undefined;

        const r = await mtlsRequest({
          host:   INTER_HOST,
          path,
          method: method || "GET",
          body:   bodyStr,
          token,
          certPem,
          keyPem,
          extraHeaders,
        });

        res.writeHead(r.status, { "Content-Type": "application/json" });
        res.end(r.body); return;
      }

    } catch (e) {
      console.error("Inter Proxy erro:", e.message);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message })); return;
    }
  }

  res.writeHead(400); res.end(JSON.stringify({ error: `Ação desconhecida: ${action}` }));
});

server.listen(PORT, () => console.log(`mTLS Proxy (C6 + Inter) rodando na porta ${PORT}`));
