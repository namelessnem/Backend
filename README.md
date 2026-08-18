# Lua Script Backend

For GitHub/Vercel setup, keep `server.js`, `package.json`, `README.md`, and your `.lua` scripts in the repository root if uploading folders from mobile is difficult.

Required environment variables in Vercel:
- HMAC_SECRET
- ADMIN_SECRET
- MAX_SCRIPT_SIZE (optional, default 1048576)

The API endpoint is `/script?id=<id>&exp=<unix>&token=<hmac>`.

For production on Vercel, use persistent object storage (such as Vercel Blob) for scripts uploaded after deployment. The included root-file fallback is useful for scripts committed to the repository.
