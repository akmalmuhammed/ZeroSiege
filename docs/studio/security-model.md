# Shannon Studio Security Model

## Access Model

- Single-admin mode
- Credentials provided via environment variables
- Session tokens signed with HMAC SHA-256 and stored in HTTP-only cookies

## Route Protection

- Middleware blocks all pages and APIs except:
  - `/login`
  - `/api/auth/login`
  - `/api/system/health`

## Credential Handling

- API/model credentials remain in server environment only
- Studio never persists model keys in browser storage

## Filesystem Safety

- Workspace and manual source identifiers are pattern-validated
- Safe path joins enforce root-directory boundaries
- Path traversal attempts fail fast

## Operational Safety

- UI runbooks explicitly require staging/local target environments
- Production-target scanning is disallowed by policy guidance
- Human validation is still required before acting on report severity
