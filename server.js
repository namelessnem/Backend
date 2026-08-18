import express from "express";
import crypto from "crypto";
import { get, put, del } from "@vercel/blob";
import { Readable } from "node:stream";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.HMAC_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const MAX_SCRIPT_SIZE = Number(process.env.MAX_SCRIPT_SIZE || 1048576);

if (!HMAC_SECRET || !ADMIN_SECRET || !process.env.BLOB_READ_WRITE_TOKEN) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

app.use(express.json({ limit: "2mb" }));

function safeId(id) {
  return typeof id === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(id);
}

function sign(id, exp) {
  return crypto.createHmac("sha256", HMAC_SECRET)
    .update(`${id}:${exp}`, "utf8")
    .digest("hex");
}

function validToken(id, exp, token) {
  if (!safeId(id) || !/^[0-9]+$/.test(String(exp)) || typeof token !== "string") return false;
  const expected = sign(id, String(exp));
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token));
  } catch {
    return false;
  }
}

function adminAuth(req, res, next) {
  if (req.get("x-admin-secret") !== ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "Lua Script API",
    endpoint: "/script?id=<id>&exp=<unix>&token=<hmac>"
  });
});

app.get("/script", async (req, res) => {
  const { id, exp, token } = req.query;

  if (!safeId(id) || !/^[0-9]+$/.test(String(exp)) || !validToken(id, exp, token)) {
    return res.status(403).send("Access Denied");
  }

  const expires = Number(exp);
  if (!Number.isSafeInteger(expires) || expires < Math.floor(Date.now() / 1000)) {
    return res.status(403).send("Access Denied");
  }

  try {
    const result = await get(`${id}.lua`, { access: "private" });
    if (!result || result.statusCode !== 200) {
      return res.status(404).send("Script Not Found");
    }

    res.setHeader("Content-Type", result.blob.contentType || "text/plain; charset=utf-8");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, no-store");
    Readable.fromWeb(result.stream).pipe(res);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.post("/admin/sign", adminAuth, (req, res) => {
  const { id, ttlSeconds = 3600 } = req.body || {};
  if (!safeId(id)) return res.status(400).json({ error: "Invalid script id" });

  const ttl = Number(ttlSeconds);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 86400) {
    return res.status(400).json({ error: "ttlSeconds must be between 1 and 86400" });
  }

  const exp = Math.floor(Date.now() / 1000) + ttl;
  const token = sign(id, String(exp));
  const baseUrl = `${req.protocol}://${req.get("host")}`;

  res.json({
    ok: true,
    id,
    exp,
    token,
    url: `${baseUrl}/script?id=${encodeURIComponent(id)}&exp=${exp}&token=${token}`
  });
});

app.post("/admin/scripts/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  const content = req.body?.content;

  if (!safeId(id)) return res.status(400).json({ error: "Invalid script id" });
  if (typeof content !== "string") return res.status(400).json({ error: "content must be a string" });
  if (Buffer.byteLength(content, "utf8") > MAX_SCRIPT_SIZE) {
    return res.status(413).json({ error: "Script is too large" });
  }

  try {
    const blob = await put(`${id}.lua`, content, {
      access: "private",
      allowOverwrite: true,
      contentType: "text/plain; charset=utf-8"
    });
    res.json({ ok: true, id, pathname: blob.pathname });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

app.delete("/admin/scripts/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  if (!safeId(id)) return res.status(400).json({ error: "Invalid script id" });

  try {
    await del(`${id}.lua`);
    res.json({ ok: true, id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Delete failed" });
  }
});

app.listen(PORT, () => console.log(`Lua Script API listening on port ${PORT}`));
