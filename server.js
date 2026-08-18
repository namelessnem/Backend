import express from "express";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.HMAC_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const MAX_SCRIPT_SIZE = Number(process.env.MAX_SCRIPT_SIZE || 1048576);

if (!HMAC_SECRET || !ADMIN_SECRET) {
  console.error("Missing HMAC_SECRET or ADMIN_SECRET.");
  process.exit(1);
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_DIR = path.join(__dirname, "scripts");

app.use(express.json({ limit: "2mb" }));

function safeId(id) {
  return typeof id === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(id);
}

function expectedToken(id, exp) {
  return crypto
    .createHmac("sha256", HMAC_SECRET)
    .update(`${id}:${exp}`, "utf8")
    .digest("hex");
}

function validToken(id, exp, token) {
  if (!safeId(id) || !/^[0-9]+$/.test(String(exp)) || typeof token !== "string") {
    return false;
  }

  const expected = expectedToken(id, String(exp));

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, "utf8"),
      Buffer.from(token, "utf8")
    );
  } catch {
    return false;
  }
}

async function scriptPath(id) {
  return path.join(SCRIPT_DIR, `${id}.lua`);
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
  const now = Math.floor(Date.now() / 1000);

  if (!Number.isSafeInteger(expires) || expires < now) {
    return res.status(403).send("Access Denied");
  }

  try {
    const file = await fs.readFile(await scriptPath(id), "utf8");

    if (Buffer.byteLength(file, "utf8") > MAX_SCRIPT_SIZE) {
      return res.status(500).send("Script Too Large");
    }

    res.type("text/plain").send(file);
  } catch (err) {
    if (err.code === "ENOENT") {
      return res.status(404).send("Script Not Found");
    }

    console.error(err);
    return res.status(500).send("Server Error");
  }
});

function adminAuth(req, res, next) {
  const supplied = req.get("x-admin-secret");

  if (!supplied || supplied !== ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
}

app.post("/admin/scripts/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  const content = req.body?.content;

  if (!safeId(id)) {
    return res.status(400).json({ error: "Invalid script id" });
  }

  if (typeof content !== "string") {
    return res.status(400).json({ error: "content must be a string" });
  }

  if (Buffer.byteLength(content, "utf8") > MAX_SCRIPT_SIZE) {
    return res.status(413).json({ error: "Script is too large" });
  }

  await fs.mkdir(SCRIPT_DIR, { recursive: true });
  await fs.writeFile(await scriptPath(id), content, "utf8");

  res.json({ ok: true, id });
});

app.delete("/admin/scripts/:id", adminAuth, async (req, res) => {
  const { id } = req.params;

  if (!safeId(id)) {
    return res.status(400).json({ error: "Invalid script id" });
  }

  try {
    await fs.unlink(await scriptPath(id));
    res.json({ ok: true, id });
  } catch (err) {
    if (err.code === "ENOENT") {
      return res.status(404).json({ error: "Script not found" });
    }

    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Lua Script API listening on port ${PORT}`);
});
