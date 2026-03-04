"use strict";

const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const PORT = process.env.PORT || 8080;

// السيرفر يحدد timeout داخليًا (العميل لا يتحكم) — عدّلها كما تريد
const SERVER_TIMEOUT_MS = Number(process.env.SERVER_TIMEOUT_MS || 20000);

// =====================
// إعدادات بسيطة
// =====================
const NODE_TOKENS = new Map([
  ["node-001", "NODE_SECRET_001"],
]);

const PUBLIC_API_KEYS = new Set([
  "PUBLIC_API_KEY_1",
]);

// =====================
// حالة الاتصالات
// =====================
const nodes = new Map();     // nodeId -> { ws, connectedAt }
const pending = new Map();   // requestId -> { resolve, reject, timeoutId, nodeId, startedAt, routeName }

// =====================
// Express
// =====================
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));

// app.get("/health", (req, res) => {
//   res.json({
//     ok: true,
//     nodes: [...nodes.keys()],
//     pending: pending.size,
//     serverTimeoutMs: SERVER_TIMEOUT_MS,
//     time: new Date().toISOString(),
//   });
// });

function requireApiKey(req, res) {
  const apiKey = req.header("x-api-key") || "";
  if (!PUBLIC_API_KEYS.has(apiKey)) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

// اختيار العقدة الوحيدة المتصلة (أول عقدة)
function getSingleConnectedNode() {
  const first = nodes.entries().next();
  if (first.done) return null;

  const [nodeId, node] = first.value;
  if (!node || !node.ws || node.ws.readyState !== WebSocket.OPEN) return null;

  return { nodeId, node };
}

// ✅ تحقق requestId (تعديل حسب احتياجك)
function normalizeAndValidateRequestId(input) {
  if (input === undefined || input === null || input === "") return null;

  const rid = String(input).trim();

  // طول منطقي
  if (rid.length < 4 || rid.length > 128) return null;

  // مسموح: حروف/أرقام/شرطة/underscore/نقطة/دولار (خفيفة)
  // عدّل regex إذا تحب
  if (!/^[A-Za-z0-9._\-:$]+$/.test(rid)) return null;

  return rid;
}

// =====================
// HTTP Endpoints: /api و /api/cust
// يقبل من العميل: { type, requestId, payload, meta }
// =====================
async function handleHttpApi(req, res, routeName) {
  try {
    if (!requireApiKey(req, res)) return;

    const target = getSingleConnectedNode();
    if (!target) {
      return res.status(503).json({ error: "Node not connected" });
    }
    const { nodeId } = target;

    const clientType = String(req.body?.type || "").trim();
    const clientPayload = req.body?.payload ?? {};
    const clientMeta = req.body?.meta ?? null;

    if (!clientType) {
      return res.status(400).json({ error: "Missing 'type' in body" });
    }

    // ✅ requestId من العميل (إذا غير موجود نولّد واحد)
    const ridFromClient = normalizeAndValidateRequestId(req.body?.requestId);
    const requestId = ridFromClient || crypto.randomUUID();

    // ✅ امنع التكرار إذا نفس requestId ما زال pending
    if (pending.has(requestId)) {
      return res.status(409).json({
        error: "Duplicate requestId (already pending)",
        requestId
      });
    }

    // timeout داخلي (العميل لا يتحكم)
    const timeoutMs = SERVER_TIMEOUT_MS;

    const webReq = {
      type: clientType,
      requestId,
      payload: clientPayload,
      meta: clientMeta,
    };

    // (اختياري) نضيف route داخليًا (يساعد C# يفرق بين api و cust)
    if (!webReq.meta) webReq.meta = {};
    webReq.meta._route = routeName;

    const result = await sendAndWait(nodeId, webReq, timeoutMs, routeName);

    const status = result && result.success ? 200 : 400;
    return res.status(status).json(result);
  } catch (err) {
    console.error(`[HTTP ${routeName}]`, err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}

app.post("/api", (req, res) => handleHttpApi(req, res, "api"));
app.post("/api/cust", (req, res) => handleHttpApi(req, res, "cust"));

// =====================
// HTTP Server + WS Server
// =====================
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });

wss.on("connection", (ws) => {
  ws.isAuthed = false;
  ws.nodeId = null;

  ws.on("message", (buf) => {
    let msg;
    try {
      msg = JSON.parse(buf.toString("utf8"));
    } catch {
      safeSend(ws, { type: "error", error: "Invalid JSON" });
      return;
    }

    // ===== AUTH =====
    if (!ws.isAuthed) {
      if (msg?.type !== "auth") {
        safeSend(ws, { type: "error", error: "Auth required" });
        ws.close(1008, "Auth required");
        return;
      }

      const nodeId = String(msg.nodeId || "");
      const token = String(msg.token || "");
      const expected = NODE_TOKENS.get(nodeId);

      if (!nodeId || !expected || token !== expected) {
        safeSend(ws, { type: "error", error: "Invalid credentials" });
        ws.close(1008, "Invalid credentials");
        return;
      }

      // اقفل اتصال قديم لنفس node
      const existing = nodes.get(nodeId);
      if (existing?.ws && existing.ws.readyState === WebSocket.OPEN) {
        try { existing.ws.close(1000, "Replaced"); } catch {}
      }

      ws.isAuthed = true;
      ws.nodeId = nodeId;
      nodes.set(nodeId, { ws, connectedAt: Date.now() });

      safeSend(ws, { type: "authed", nodeId });
      console.log(`[WS] Node connected: ${nodeId}`);
      return;
    }

    // ===== RESPONSE FROM NODE =====
    const requestId = String(msg.requestId || "");
    if (!requestId) return;

    const entry = pending.get(requestId);
    if (!entry) return;

    if (entry.nodeId !== ws.nodeId) return;

    clearTimeout(entry.timeoutId);
    pending.delete(requestId);
    entry.resolve(msg);
  });

  ws.on("close", () => {
    if (ws.isAuthed && ws.nodeId) {
      nodes.delete(ws.nodeId);

      for (const [rid, entry] of pending.entries()) {
        if (entry.nodeId === ws.nodeId) {
          clearTimeout(entry.timeoutId);
          pending.delete(rid);
          entry.reject(new Error("Node disconnected"));
        }
      }
    }
  });

  ws.on("error", (e) => console.error("[WS] error:", e));
});

// =====================
// sendAndWait
// timeoutId + nodeId داخليين دائمًا
// =====================
function sendAndWait(nodeId, webReq, timeoutMs, routeName) {
  return new Promise((resolve, reject) => {
    const node = nodes.get(nodeId);
    if (!node || !node.ws || node.ws.readyState !== WebSocket.OPEN) {
      reject(new Error("Node not connected"));
      return;
    }

    const requestId = String(webReq.requestId || crypto.randomUUID());
    webReq.requestId = requestId;

    const timeoutId = setTimeout(() => {
      pending.delete(requestId);
      reject(new Error("Timeout"));
    }, timeoutMs);

    pending.set(requestId, {
      resolve,
      reject,
      timeoutId,   // داخلي
      nodeId,      // داخلي
      startedAt: Date.now(),
      routeName,
    });

    safeSend(node.ws, webReq);
  }).catch((err) => {
    return {
      requestId: webReq.requestId,
      success: false,
      data: null,
      error: err.message || "Error",
      errorCodes: err.message === "Timeout" ? "TIMEOUT" : "GATEWAY_ERROR",
    };
  });
}

function safeSend(ws, obj) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  } catch (e) {
  }
}

server.listen(PORT, () => {
  console.log(`Gateway running on :${PORT}`);
  console.log(`HTTP  => POST http://localhost:${PORT}/api`);
  console.log(`HTTP  => POST http://localhost:${PORT}/api/cust`);
  console.log(`WS    => ws://localhost:${PORT}/ws`);
  console.log(`SERVER_TIMEOUT_MS = ${SERVER_TIMEOUT_MS}`);
});