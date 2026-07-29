# Architecture

## Security boundary

The broker is the only component permitted to hold the DingTalk application
secret or request an OA attachment download URL. Clients hold only opaque,
short-lived broker credentials.

```mermaid
flowchart LR
    Client["Skill or CLI"] -->|Device code and broker token| Ingress["TLS ingress"]
    Ingress --> Broker["OA attachment broker"]
    Broker --> Catalog["Per-user in-memory visible catalog"]
    Broker --> Policy["Participant authorization"]
    Broker --> DB[("Dedicated PostgreSQL")]
    Broker --> PrivateMetrics["Private metrics listener on port 9090"]
    Prometheus["Prometheus Operator"] -->|ServiceMonitor| PrivateMetrics
    Blackbox["Blackbox exporter"] -->|Public readiness probe| Ingress
    Broker -->|Application token| DingAPI["DingTalk OpenAPI"]
    DingAPI -->|User-visible approval templates| Catalog
    DingAPI -->|Temporary signed URL| Broker
    Broker -->|Validated byte stream| Client
    Secret["Pre-created Kubernetes Secret"] --> Broker
    Config["Deployment administrator user IDs"] --> Policy
```

The service has no approval mutation dependency and does not expose endpoints
for create, agree, reject, return, or transfer actions.

## Device authorization sequence

```mermaid
sequenceDiagram
    actor User
    participant Client as Skill or CLI
    participant Broker
    participant DB as PostgreSQL
    participant DingTalk

    Client->>Broker: POST /api/v1/device-authorizations
    Broker->>DB: Store HMAC(device code), user code, expiry
    Broker-->>Client: Device code and verification URI
    User->>Broker: GET /auth/dingtalk/start?user_code=...
    Broker->>DB: Bind single-use HMAC(OAuth state)
    Broker-->>User: 303 DingTalk authorization
    User->>DingTalk: Authenticate and consent
    DingTalk-->>Broker: Callback with code and state
    Broker->>DB: Atomically claim HMAC(OAuth state)
    Broker->>DingTalk: Exchange code for user token
    Broker->>DingTalk: Get current unionId and corpId
    Broker->>DingTalk: Map unionId to enterprise userId
    Broker->>DB: Store verified user and approve device code
    Broker-->>User: Authorization complete
    Client->>Broker: Poll device authorization token endpoint
    Broker->>DB: Atomically consume device code and create session hashes
    Broker-->>Client: Opaque access and refresh tokens
```

The DingTalk user token exists only within the callback request. The database
contains only HMAC values for device, OAuth state, access, and refresh
credentials.
Consent denial and failures after state claim move the device authorization to
a terminal denied state, so polling clients stop immediately instead of waiting
for expiry.

## Attachment download sequence

```mermaid
sequenceDiagram
    participant Client as Authenticated client
    participant Broker
    participant DB as PostgreSQL
    participant DingTalk
    participant Storage as Signed URL target

    Client->>Broker: GET approval attachment content
    Broker->>DB: Authenticate HMAC(access token)
    Broker->>DingTalk: Get process instance details
    Broker->>Broker: Verify participant or configured administrator
    Broker->>Broker: Verify fileId belongs to processInstanceId
    Broker->>DingTalk: Grant temporary attachment download
    DingTalk-->>Broker: Temporary signed URL
    Broker->>Broker: Validate HTTPS, redirects, DNS answers, and size
    Broker->>Storage: Open validated upstream stream
    Broker->>DB: Record allowed decision
    Broker-->>Client: Stream bytes with sanitized filename
```

Denied requests are audited with a stable error category. Tokens, URL query
signatures, form content, and attachment bytes are not audit fields.

## Category search sequence

```mermaid
sequenceDiagram
    participant Client as Authenticated client
    participant Broker
    participant DB as PostgreSQL
    participant DingTalk

    Client->>Broker: GET /api/v1/approvals?category=...
    Broker->>DB: Authenticate HMAC(access token)
    Broker->>Broker: Resolve opaque category to one visible template
    Broker->>DingTalk: List bounded IDs for selected visible template
    loop At most 20 candidates
        Broker->>DingTalk: Get process instance details
        Broker->>Broker: Verify participant or administrator
        Broker->>DB: Audit allowed or denied decision
    end
    Broker-->>Client: Authorized summaries, attachments, signed cursor
```

One request inspects at most 20 candidate instances. Work is distributed
within the selected user-visible template, detail calls use bounded
concurrency, and each user is limited to six search requests per minute per
replica by default.

## Current-user category discovery

```mermaid
sequenceDiagram
    participant Client as Authenticated client
    participant Broker
    participant DB as PostgreSQL
    participant DingTalk

    Client->>Broker: GET /api/v1/me/approval-categories
    Broker->>DB: Authenticate HMAC(access token)
    Broker->>Broker: Bind catalog to corpId and userId hash
    loop DingTalk form pages, bounded to 100
        Broker->>DingTalk: List user-visible approval templates
    end
    Broker->>Broker: HMAC processCode into opaque user-bound category ID
    Broker-->>Client: Template names, directories, complete, nextCursor
```

The catalog contains only templates DingTalk reports visible to the current
enterprise `userId`. It is cached in memory for one minute, capped at 5,000
templates, and never persisted. Each API page returns at most one hundred
categories. Category and approval-search cursors contain only a hash of the
enterprise subject, expire after one hour, and are rejected when used by a
different `corpId` or `userId`.

## Package boundaries

```mermaid
flowchart TD
    Main["cmd/server"] --> Config["internal/config"]
    Main --> Auth["internal/auth"]
    Main --> ApprovalSearch["internal/approvals"]
    Main --> Attachments["internal/attachments"]
    Main --> DingTalk["internal/dingtalk"]
    Main --> PostgreSQL["internal/postgres"]
    Main --> HTTP["internal/httpapi"]
    Main --> Lifecycle["internal/server"]
    HTTP --> Auth
    HTTP --> ApprovalSearch
    HTTP --> Attachments
    Auth --> PostgreSQL
    Auth --> DingTalk
    Attachments --> DingTalk
    Attachments --> PostgreSQL
    ApprovalSearch --> DingTalk
    ApprovalSearch --> PostgreSQL
    PostgreSQL --> Domain["internal/domain"]
    DingTalk --> Domain
```

## Data model

```mermaid
erDiagram
    USERS ||--o{ DEVICE_AUTHORIZATIONS : verifies
    USERS ||--o{ SESSIONS : owns
    USERS {
        text corp_id PK
        text user_id PK
        text union_id
        text display_name
        timestamptz updated_at
    }
    DEVICE_AUTHORIZATIONS {
        bytea device_code_hash PK
        text user_code
        bytea oauth_state_hash
        text status
        timestamptz expires_at
    }
    SESSIONS {
        bigint id PK
        bytea access_token_hash
        bytea refresh_token_hash
        timestamptz access_expires_at
        timestamptz refresh_expires_at
        timestamptz revoked_at
    }
    AUDIT_EVENTS {
        bigint id PK
        text request_id
        text actor_user_id
        text action
        text process_instance_id
        text file_id
        text decision
        text upstream_error_class
        timestamptz created_at
    }
```

Migrations are embedded in the migration binary. They are forward-only and
serialized with a PostgreSQL advisory lock.

Expired device authorizations and sessions past their refresh or revocation
retention are removed by the application once per day. Audit events use a
separate, longer retention window. Cleanup queries are supported by migration
managed indexes and preserve every active or refreshable session.
