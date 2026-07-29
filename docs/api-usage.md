# API Usage

## Device login

Set the canonical broker URL.

```bash
export BROKER_URL="https://broker.example.com"
```

Create a device authorization.

```bash
curl --fail --silent --show-error \
  --request POST \
  "${BROKER_URL}/api/v1/device-authorizations"
```

Open `verificationUriComplete` in a browser and complete DingTalk login. Poll
the token endpoint no faster than the returned `interval`.

```bash
curl --fail-with-body --silent --show-error \
  --request POST \
  --header "Content-Type: application/json" \
  --data '{"deviceCode":"replace-with-device-code"}' \
  "${BROKER_URL}/api/v1/device-authorizations/token"
```

An authorization that is not complete returns HTTP 428 with
`authorization_pending`. Device codes expire after ten minutes and are
single-use.

## Current identity

```bash
curl --fail --silent --show-error \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  "${BROKER_URL}/api/v1/me"
```

The returned `userId` is the enterprise identity used for authorization. Client
input cannot override it.

## Compatibility category endpoint

```bash
curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  "${BROKER_URL}/api/v1/approval-categories"
```

This endpoint is a compatibility alias for
`/api/v1/me/approval-categories`. New clients should use the user-scoped path.

## Discover categories visible to the current user

Read approval templates visible to the authenticated DingTalk user:

```bash
curl --fail-with-body --silent --show-error \
  --get \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  --data-urlencode "q=firmware" \
  "${BROKER_URL}/api/v1/me/approval-categories"
```

The optional `q` parameter filters the approval-template name and DingTalk
directory name. Every returned template has a user-bound opaque category ID;
the raw DingTalk `processCode` is not returned. `totalCategories` reports the
number of matching templates, and each API page returns at most 100 entries.
The catalog is cached for one minute. A visible category may have no recent
approval with an attachment; the search endpoint performs that filtering.

When `complete` is false, follow `nextCursor` unchanged:

```bash
curl --fail-with-body --silent --show-error \
  --get \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  --data-urlencode "cursor=${NEXT_CURSOR}" \
  "${BROKER_URL}/api/v1/me/approval-categories"
```

Omit `q` when continuing. The signed cursor
expires after one hour and is bound to the authenticated `corpId` and `userId`.
Changing users invalidates it.

## Search approvals by category

First obtain the current user's opaque category ID, then search the default
120-day window:

```bash
curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  "${BROKER_URL}/api/v1/approvals?category=${CATEGORY_ID}&limit=20"
```

Use `q` to match an approval title, visible approval number (`businessId`), or
form value after participant authorization:

```bash
curl --fail-with-body --silent --show-error \
  --get \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  --data-urlencode "category=${CATEGORY_ID}" \
  --data-urlencode "q=T120" \
  --data-urlencode "limit=20" \
  "${BROKER_URL}/api/v1/approvals"
```

Use explicit RFC3339 bounds when a narrower window is appropriate:

```bash
curl --fail-with-body --silent --show-error \
  --get \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  --data-urlencode "category=${CATEGORY_ID}" \
  --data-urlencode "createdAfter=2026-06-01T00:00:00+08:00" \
  --data-urlencode "createdBefore=2026-07-01T00:00:00+08:00" \
  --data-urlencode "limit=20" \
  "${BROKER_URL}/api/v1/approvals"
```

Only approvals that pass participant authorization and contain at least one
attachment are returned. Use `nextCursor` unchanged for the next page and omit
the time bounds:

```bash
curl --fail-with-body --silent --show-error \
  --get \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  --data-urlencode "category=${CATEGORY_ID}" \
  --data-urlencode "cursor=${NEXT_CURSOR}" \
  --data-urlencode "limit=20" \
  "${BROKER_URL}/api/v1/approvals"
```

The cursor expires after one hour and is bound to the authenticated user,
category, keyword, time window, and category revision. Cursors from older
Broker versions are rejected with HTTP 400; restart the query from its first
page. Omit `q` and the time bounds when continuing. A single search window
cannot exceed 120 days, and `createdAfter` cannot be more than 365 days in the
past.

## List approval attachments

Use a DingTalk `processInstanceId`, not the visible approval number or
`businessId`. Never pass a template `processCode`; values beginning with
`PROC-` are rejected before the broker calls DingTalk.

```bash
export PROCESS_INSTANCE_ID="replace-with-process-instance-id"

curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  "${BROKER_URL}/api/v1/approvals/${PROCESS_INSTANCE_ID}/attachments"
```

Attachments found in form values have source `form`. Attachments found in
operation records and comments have source `comment`.

## Download an attachment

```bash
export FILE_ID="replace-with-file-id"

curl --fail-with-body --location \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  --output "attachment.download" \
  "${BROKER_URL}/api/v1/approvals/${PROCESS_INSTANCE_ID}/attachments/${FILE_ID}/content"
```

The broker re-reads the approval before the download. A `fileId` that does not
belong to the approval returns HTTP 404. The response contains attachment bytes,
not a DingTalk signed URL.

## Refresh and revoke

Refresh tokens rotate on every successful use.

```bash
curl --fail-with-body --silent --show-error \
  --request POST \
  --header "Content-Type: application/json" \
  --data '{"refreshToken":"replace-with-current-refresh-token"}' \
  "${BROKER_URL}/api/v1/sessions/refresh"
```

Revoke the current session when it is no longer needed.

```bash
curl --fail --silent --show-error \
  --request DELETE \
  --header "Authorization: Bearer ${BROKER_ACCESS_TOKEN}" \
  "${BROKER_URL}/api/v1/sessions/current"
```

## Error contract

Errors use `application/problem+json`. `requestId` matches the
`X-Request-ID` response header and is the safe value to provide to operators.

```json
{
  "type": "/problems/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "Access to this resource is denied.",
  "instance": "/api/v1/approvals/example/attachments",
  "code": "forbidden",
  "requestId": "9f6ee7f7b1fb4bf98f051ab04179b23b"
}
```

The service intentionally does not expose upstream error messages, credentials,
or signed URL details.
