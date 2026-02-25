# Shannon Studio VPS Deployment

## 1. Host Prerequisites

- Linux VPS with Docker and Docker Compose plugin
- Public DNS record for your Studio domain
- Outbound network access for model APIs

## 2. Environment

Copy `.env.example` to `.env` and set:

- `ANTHROPIC_API_KEY` (or `CLAUDE_CODE_OAUTH_TOKEN`)
- `STUDIO_SESSION_SECRET`
- `STUDIO_ADMIN_USERNAME`
- `STUDIO_ADMIN_PASSWORD`
- `STUDIO_DOMAIN`
- `CADDY_ACME_EMAIL`

## 3. Deploy

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## 4. Validate

- `https://<your-domain>` loads login page
- `https://<your-domain>/api/system/health` returns healthy checks
- `http://<host>:8233` Temporal UI reachable (restrict in firewall if needed)

## 5. Backup Strategy

Persist and snapshot:

- `./audit-logs`
- `./repos`
- `./targets`
- Docker volume `temporal-data`
- Caddy data volume (`caddy-data`) for cert state

## 6. Restore

1. Restore bind mounts and volumes.
2. Recreate containers with the same compose command.
3. Confirm workspace list and report artifacts in Studio.
