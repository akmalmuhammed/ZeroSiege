# Shannon Studio

Shannon Studio is the web control plane for Shannon Lite.

Current run mode is URL-first. Reusing an existing workspace name for resume is intentionally disabled.

It adds:

- Single-admin authentication
- URL-first workflow launch from the browser
- Live pipeline status polling via Temporal
- Workspace history, report browsing, and log tailing
- Guided tutorials for each core feature

## Run Locally

1. Fill root `.env` with Anthropic credentials.
2. Set Studio credentials in `.env`:

```bash
STUDIO_SESSION_SECRET=<long-random-secret>
STUDIO_ADMIN_USERNAME=admin
STUDIO_ADMIN_PASSWORD=<strong-password>
```

3. Start services:

```bash
./shannon studio up
```

4. Open:

- Studio UI: `http://localhost:3005`
- Temporal UI: `http://localhost:8233`

## Development

For frontend-only iteration:

```bash
cd studio
npm install
npm run dev
```

The app expects these mounted directories (or matching env vars):

- `../audit-logs`
- `../repos`
- `../configs`
- `../sample-reports`
- `../targets`

## Production

Use:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Then configure:

- `STUDIO_DOMAIN`
- `CADDY_ACME_EMAIL`

See:

- `docs/studio/deployment-vps.md`
