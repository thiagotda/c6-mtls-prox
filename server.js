```js
const https = require("https");
const http = require("http");
const { URLSearchParams } = require("url");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.PROXY_SECRET || "";

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
        ...(token ? { "Authorization": Bearer ${token} } : {}),
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

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
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
