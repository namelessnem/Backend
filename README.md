# Lua Script Backend

A small external backend for serving Lua scripts through an HMAC-signed URL.

## 1. Install

```bash
npm install
```

Copy `.env.example` to `.env` and set:

- `HMAC_SECRET` — secret used to sign script URLs
- `ADMIN_SECRET` — secret used to upload/delete scripts

Use long random values for both.

## 2. Add a script

Create:

```text
scripts/my-script.lua
```

Or upload one through the admin API:

```bash
curl -X POST "https://YOUR-DOMAIN/admin/scripts/my-script" \
  -H "Content-Type: application/json" \
  -H "x-admin-secret: YOUR_ADMIN_SECRET" \
  --data '{"content":"print(\"hello\")"}'
```

## 3. Generate an access URL

The token is:

```text
HMAC-SHA256(HMAC_SECRET, id + ":" + exp)
```

For example, for:

```text
id = my-script
exp = 1787050000
```

sign:

```text
my-script:1787050000
```

and use:

```text
https://YOUR-DOMAIN/script?id=my-script&exp=1787050000&token=GENERATED_HEX_TOKEN
```

The backend rejects:

- missing/invalid IDs
- invalid HMAC signatures
- expired timestamps
- unknown scripts

## Important deployment note

This version stores scripts on the server filesystem. On hosts with ephemeral filesystems, such as some container deployments, uploaded files can disappear after a redeploy/restart.

For production, use persistent storage such as a database, object storage, or a persistent disk.

## Railway / Render

Set the environment variables from `.env.example`, then deploy the repository. The platform should run:

```text
npm start
```

The server listens on the platform-provided `PORT`.
