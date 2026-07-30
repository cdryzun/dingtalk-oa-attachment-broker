# DingTalk OA Attachment Broker

[![CI](https://github.com/cdryzun/dingtalk-oa-attachment-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/cdryzun/dingtalk-oa-attachment-broker/actions/workflows/ci.yml)

`dingtalk-oa-attachment-broker` is a self-hosted security boundary between
authenticated users or AI agents and DingTalk OA approval attachments. It
verifies enterprise identity, applies default-deny participant authorization,
and streams authorized attachments without exposing the DingTalk application
secret, application token, user token, or signed download URL.

This repository does not provide a shared hosted Broker. Each organization
creates its own DingTalk internal application and deploys a Broker dedicated to
its own enterprise.

## Architecture

```mermaid
flowchart LR
    Agent["AI agent or CLI"] -->|Device authorization and Broker token| Broker
    User["Enterprise user"] -->|DingTalk OAuth| Broker
    Broker -->|Identity and approval APIs| DingTalk
    Broker -->|Session and audit state| PostgreSQL[(PostgreSQL)]
    Broker -->|Validated attachment stream| Agent
```

The Broker is read-only. It has no endpoint for creating, approving, rejecting,
returning, or transferring OA approvals, and it never persists attachment
content.

## Capabilities

- DingTalk OAuth device authorization with enterprise `corpId`, `unionId`, and
  `userId` verification.
- Rotating Broker access and refresh tokens stored as HMAC values.
- Discovery of approval templates visible to the authenticated user.
- Bounded approval search with signed, user-bound cursors.
- Originator, approver, task user, CC user, and configured administrator access.
- Attachment membership revalidation before every download.
- HTTPS-only, public-address-only upstream streaming with redirect, DNS, size,
  and timeout controls.
- PostgreSQL audit records without tokens, signed URLs, form content, or
  attachment bytes.
- JSON logs, request IDs, Prometheus metrics, health checks, and graceful
  shutdown.
- A dependency-free Python client packaged as an Agent Skill.

Direct attachment access accepts only a DingTalk `processInstanceId`. A visible
OA approval number is a `businessId`, not an API identifier. DingTalk limits one
approval-list query to a 120-day window and rejects start times more than 365
days in the past.

## Requirements

- Go 1.25 or newer for source builds.
- PostgreSQL 14 or newer; use a currently supported major version in production.
- Docker or another OCI builder for container builds.
- Python 3.9 or newer only when using the bundled Skill client.
- A public HTTPS origin for the DingTalk OAuth callback.

## Quick Start

1. Create a DingTalk enterprise internal application and grant the read-only
   permissions listed in [DingTalk application setup](docs/dingtalk-application.md).
2. Register `https://broker.example.com/auth/dingtalk/callback`, replacing the
   example origin with the deployment's `PUBLIC_BASE_URL`.
3. Create a dedicated PostgreSQL database and generate a token pepper.
4. Apply migrations, then start the Broker.
5. Configure the Agent or CLI with that same Broker origin.

For local source development:

```bash
export PUBLIC_BASE_URL="http://127.0.0.1:8080"
export DINGTALK_CLIENT_ID="replace-with-development-client-id"
export DINGTALK_CLIENT_SECRET="replace-with-development-client-secret"
export DINGTALK_CORP_ID="replace-with-enterprise-corp-id"
export DATABASE_URL="postgres://broker:replace-me@127.0.0.1:5432/broker?sslmode=disable"
export TOKEN_PEPPER="$(openssl rand -base64 48)"

go run ./cmd/migrate
go run ./cmd/server
```

Verify the process and schema:

```bash
curl --fail --silent http://127.0.0.1:8080/healthz
curl --fail --silent http://127.0.0.1:8080/readyz
curl --fail --silent http://127.0.0.1:9090/metrics
```

Loopback HTTP is accepted only for local callback testing. Every non-loopback
`PUBLIC_BASE_URL` must use HTTPS.

## Agent and CLI Client

The bundled Skill requires the operator-provided Broker origin. It has no public
default and will fail with `missing_broker_url` when the origin is absent.

```bash
export DINGTALK_OA_BROKER_URL="https://broker.example.com"
python3 skills/dingtalk-oa-attachment/scripts/dingtalk_oa_attachment.py login
python3 skills/dingtalk-oa-attachment/scripts/dingtalk_oa_attachment.py auth-status
```

The client stores only Broker access and refresh tokens in a local,
user-restricted JSON file. It never receives the DingTalk AppSecret or a signed
attachment URL. See [Skill integration](docs/skill-integration.md) for the full
contract.

## Configuration

Required values:

| Variable | Purpose |
| --- | --- |
| `PUBLIC_BASE_URL` | Public Broker origin used for OAuth callbacks |
| `DINGTALK_CLIENT_ID` | DingTalk internal application client ID |
| `DINGTALK_CLIENT_SECRET` | DingTalk internal application client secret |
| `DINGTALK_CORP_ID` | The only enterprise accepted by this deployment |
| `DATABASE_URL` | Dedicated PostgreSQL connection URL |
| `TOKEN_PEPPER` | HMAC key material containing at least 32 bytes |

Optional values:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `HTTP_ADDRESS` | `:8080` | Public HTTP listen address |
| `METRICS_ADDRESS` | `:9090` | Private Prometheus listen address |
| `HTTP_READ_HEADER_TIMEOUT` | `5s` | Request header deadline |
| `HTTP_READ_TIMEOUT` | `15s` | Complete request read deadline |
| `HTTP_IDLE_TIMEOUT` | `60s` | Keep-alive idle deadline |
| `SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown deadline |
| `READINESS_TIMEOUT` | `2s` | PostgreSQL readiness deadline |
| `DEVICE_CODE_TTL` | `10m` | Whole-second device/OAuth lifetime; min `1s` |
| `ACCESS_TOKEN_TTL` | `8h` | Whole-second access lifetime; min `1s` |
| `REFRESH_TOKEN_TTL` | `720h` | Whole-second refresh lifetime; min `1s` |
| `AUTH_POLL_INTERVAL` | `5s` | Whole seconds; min `1s`, less than device TTL |
| `UPSTREAM_TIMEOUT` | `30s` | DingTalk API deadline; min `1ms` |
| `DOWNLOAD_TIMEOUT` | `10m` | End-to-end attachment deadline |
| `DOWNLOAD_MAX_BYTES` | `209715200` | Maximum streamed attachment bytes |
| `DOWNLOAD_CONCURRENCY_PER_USER` | `5` | Active streams allowed per user |
| `REQUESTS_PER_MINUTE` | `120` | Per-source limit, including `/readyz` |
| `TRUSTED_PROXY_CIDRS` | empty | Proxies allowed to supply client addresses |
| `AUDIT_RETENTION` | `4320h` | Audit retention interval |
| `AUTH_RECORD_RETENTION` | `168h` | Expired authentication record retention |
| `APPROVAL_SEARCH_CONCURRENCY` | `4` | Concurrent candidate detail checks |
| `APPROVAL_SEARCH_REQUESTS_PER_MINUTE` | `6` | Per-user search limit |
| `DINGTALK_ADMIN_USER_IDS` | empty | Audited administrator user IDs |
| `DINGTALK_API_ENDPOINT` | `api.dingtalk.com` | DingTalk OpenAPI SDK endpoint |
| `DINGTALK_OAPI_BASE_URL` | DingTalk OAPI | Union ID mapping endpoint |
| `DINGTALK_OAUTH_AUTHORIZE_URL` | DingTalk login | OAuth endpoint |

`DINGTALK_ADMIN_USER_IDS` is a security-sensitive deployment input. Review each
change like an application permission change. The public listener does not
serve `/metrics`; production monitoring must reach `METRICS_ADDRESS` through a
private network path.

Forwarded client addresses are ignored unless the direct peer is covered by
`TRUSTED_PROXY_CIDRS`. Configure only proxy-owned CIDRs and make the proxy append
or replace `X-Forwarded-For`; never trust a network that clients can reach
directly.

## Verification

```bash
gofmt -w cmd internal
go mod tidy
go mod verify
go vet ./...
go test -race -count=1 -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
CGO_ENABLED=0 go build -trimpath -o bin/server ./cmd/server
CGO_ENABLED=0 go build -trimpath -o bin/migrate ./cmd/migrate
```

CI requires at least 80 percent total Go statement coverage and 80 percent
Python client coverage.

## Documentation

- [Architecture](docs/architecture.md)
- [API usage](docs/api-usage.md)
- [Authorization matrix](docs/authorization.md)
- [DingTalk application setup](docs/dingtalk-application.md)
- [Deployment](docs/deployment.md)
- [Operations and rollback](docs/operations.md)
- [Security threat model](docs/threat-model.md)
- [Skill integration](docs/skill-integration.md)
- [OpenAPI contract](api/openapi.yaml)

## Security

Review [SECURITY.md](SECURITY.md) before reporting a vulnerability. Never place
DingTalk credentials, Broker tokens, approval content, or signed URLs in a
public issue.

## License

Licensed under the [Apache License 2.0](LICENSE).
