---
name: dingtalk-oa-attachment
description: Sign in to a configured self-hosted DingTalk OA Attachment Broker, discover approval templates visible to the current user, search authorized approvals, list attachments for a processInstanceId, download selected files with integrity metadata, or end the local Broker session. Use when a user asks to find, inspect, or download DingTalk OA approval attachments. This is a read-only workflow and never creates or changes approvals.
license: Apache-2.0
metadata: {title: "DingTalk OA Attachment", icon: ":lucide:paperclip:"}
---

# DingTalk OA Attachment

Use the bundled standard-library Python client. Require an operator-provided
Broker origin and never infer, discover, or substitute another deployment.

## Safety boundary

- For direct list and download operations, accept only a DingTalk
  `processInstanceId`. Do not substitute the visible OA approval number or
  `businessId`.
- For discovery, use only category IDs returned by the Broker. Never accept or
  invent a DingTalk `processCode` or local classification rule. Reject any
  direct `processInstanceId` input beginning with `PROC-`; that is a template
  code, not an approval instance.
- Never request or expose DingTalk AppSecret, app access tokens, user access
  tokens, or signed attachment URLs.
- Never print, share, or commit Broker access or refresh tokens. The client
  stores them only in the configured local JSON credential file.
- Never bypass a 403 response by matching names, phone numbers, or broadening
  membership.
- Treat list and download as read-only. This skill must not create, approve,
  reject, return, or transfer an OA approval.
- Write downloads only to the path explicitly requested by the user. The
  client refuses overwrite unless the user explicitly asks for it.

## Configuration

Use Python 3.9 or newer. Configure the HTTPS origin of the Broker deployed by
the user's enterprise. The client has no shared default.

On macOS and Linux:

```bash
export DINGTALK_OA_BROKER_URL="https://broker.example.com"
python3 scripts/dingtalk_oa_attachment.py auth-status
```

On Windows PowerShell:

```powershell
$env:DINGTALK_OA_BROKER_URL = "https://broker.example.com"
$env:DINGTALK_OA_CREDENTIAL_FILE = Join-Path `
  $env:LOCALAPPDATA "DingTalkOAAttachment\auth.json"
py -3 scripts\dingtalk_oa_attachment.py auth-status
```

Replace `https://broker.example.com` with the enterprise operator's exact
Broker origin. `DINGTALK_OA_BROKER_URL` or the global `--broker-url` option is
required. Stop on `missing_broker_url`; never guess an origin from the DingTalk
enterprise name, user input, or prior sessions.

The default credential file is `.runtime/auth.json` inside this Skill. Set
`DINGTALK_OA_CREDENTIAL_FILE` or pass the global `--credential-file` option
before the command to share one per-user cache across separate Skill copies.
The configured path must be absolute.

This JSON file is local plaintext state. Never copy it between users or place
it in Git, cloud sync, a network share, or another shared directory. On Unix,
the client creates mode `0700` directories and a mode `0600` file. On Windows,
use the current user's `%LOCALAPPDATA%` directory so the file inherits that
user's NTFS access controls.

Read [Platform and credential maintenance](references/platform-and-credential-maintenance.md)
when installing the Skill for another user, moving its credential path, or
distributing a release.

## Required workflow

1. Run `auth-status`. If it succeeds, report the returned display name and
   enterprise `userId`. If it returns `reauthentication_required`, run `login`
   and retry once.
2. For discovery, run `my-categories --all`. The Broker returns every DingTalk
   approval template visible to the authenticated user, with its display name
   and directory name. Resolve a natural-language request against every
   matching returned category and run `search` only with those opaque category
   IDs. A visible template may have zero recent approvals with attachments.
3. Follow `nextCursor` until it is absent or the user-approved scan bound is
   reached. An empty `items` page with a `nextCursor` is not evidence that the
   category has no accessible approvals. Honor 429 retry timing; do not restart
   concurrent scans to bypass the user rate limit.
4. Combine multi-category results, deduplicate by `processInstanceId`, and sort
   by `createTime` descending unless the user requests another order. Before
   asking the user to select an approval, always show its `businessId`, title,
   status, `createTime`, and `processInstanceId` together. Never return opaque
   IDs alone.
5. Treat a number copied from the DingTalk UI as a `businessId`, not as a
   `processInstanceId`. Match it against authorized search results. If no
   authorized result is found, ask for the real `processInstanceId`; never pass
   the visible number to `list` or `download`.
6. Run `list` with the selected `processInstanceId`, show attachment names and
   exact `fileId` values, then download only the files selected by the user.
7. For multiple approvals, create one destination directory per `businessId`.
   Use filenames that are valid on Windows, macOS, and Linux, and keep the
   client's no-overwrite default.
8. Run `logout` only when the user explicitly asks to end the local Broker
   session. Report whether the server session was revoked and whether the local
   credential file was removed.

## Login

```bash
python3 scripts/dingtalk_oa_attachment.py login
```

Use `py -3` instead of `python3` on Windows. The command emits JSON Lines
containing the verification URL, `browserOpenAttempted`, and `browserOpened`.
It opens the URL unless `--no-open` is supplied. If the page is blank or
`browserOpened` is false, copy `verificationUriComplete` into Edge or Chrome
and select the DingTalk avatar. Never ask the user for an AppKey or AppSecret.

A successful login creates or atomically replaces the configured JSON
credential file. Validate the result:

```bash
python3 scripts/dingtalk_oa_attachment.py auth-status
```

`auth-status` calls the Broker, refreshes the session once when necessary, and
returns the current identity without printing either token.

## Logout

```bash
python3 scripts/dingtalk_oa_attachment.py logout
```

Use `py -3` instead of `python3` on Windows. The command revokes the current
Broker session through `DELETE /api/v1/sessions/current` and then removes the
configured local credential file. It is safe to run when no credential file
exists. If the Broker reports that the session is already expired or revoked,
the client removes the stale local file.

If revocation fails because the Broker is unavailable or returns a transient
server error, the command preserves the credential file so the operation can
be retried. It never prints either token.

## List attachments

```bash
python3 scripts/dingtalk_oa_attachment.py list \
  --process-instance-id "<PROCESS_INSTANCE_ID>"
```

Use the returned `fileId` exactly as received. A 403 means the authenticated
user is not an approval participant or configured audit administrator.

## Discover and search approvals

List the first page through the compatibility command:

```bash
python3 scripts/dingtalk_oa_attachment.py categories
```

List templates visible to the current user:

```bash
python3 scripts/dingtalk_oa_attachment.py my-categories --all
```

Use `--q firmware` to filter the template name or DingTalk directory name. A
single command fetches one Broker page by default. Use `--max-pages 5` for a
bounded multi-page read,
`--cursor "<NEXT_CURSOR>"` to continue manually, or `--all` to continue until
the Broker reports `complete=true` subject to the client's 100-page safety cap.
The output reports `pagesFetched`, `totalCategories`, compatibility counters,
and the remaining `nextCursor`. Category IDs are bound to the logged-in user;
never reuse another user's category ID.

Search the default 120-day window:

```bash
python3 scripts/dingtalk_oa_attachment.py search \
  --category "<CATEGORY_ID_FROM_MY_CATEGORIES>"
```

Use `--q T120` to search authorized approval titles, visible approval numbers,
and form values within the selected category.

Use `--created-after` and `--created-before` with RFC3339 timestamps to narrow
the first search page. Use `--cursor` unchanged for the next page and omit
`--q` and both time bounds. Search and category cursors are bound to the
authenticated enterprise user and cannot be reused after switching accounts.
Older cursor versions fail closed; restart the read-only query from its first
page. Continue when `items` is empty but `nextCursor` is present. The Broker
returns only approvals that contain attachments and pass participant
authorization.

DingTalk limits one query window to 120 days and rejects start times more than
365 days in the past. Do not work around these limits with unbounded scans.
Older approvals require an already known `processInstanceId`.

## Download one attachment

```bash
python3 scripts/dingtalk_oa_attachment.py download \
  --process-instance-id "<PROCESS_INSTANCE_ID>" \
  --file-id "<FILE_ID>" \
  --output "/absolute/path/attachment.bin"
```

The client streams through a private temporary file in the destination
directory, then publishes it with an atomic no-clobber operation. On success it
prints JSON containing the absolute path, byte count, and SHA-256 digest.

Use `--overwrite` only after the user explicitly authorizes replacing the
destination file.

When a returned attachment name is not portable, replace Windows-invalid
characters (`< > : " / \ | ? *`), remove trailing dots or spaces, and avoid
reserved base names such as `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, and
`LPT1`-`LPT9`. Keep the original extension and report the final path.

## Error handling

- `401`: the client refreshes the Broker session once and atomically updates
  the configured credential file.
- `reauthentication_required`: run `login`, then retry the original command
  once. During `logout`, this means the server session is already inactive, so
  the client removes the stale local credential file.
- `credential_store_error`: do not delete or replace the file automatically.
  Report the configured path and ask the user to fix ownership, permissions, or
  choose a new per-user path.
- `403`: report that Broker authorization denied access; do not attempt a
  workaround.
- `404`: report that the approval or exact `fileId` membership was not
  confirmed.
- `invalid_process_instance_id`: the caller supplied a template `processCode`;
  return to `my-categories` and `search` to obtain a real `processInstanceId`.
- `413`: report that the attachment exceeds the Broker limit.
- `429`: retry only after the server-provided delay or a short bounded wait.
- `5xx`: report the Broker request ID. Preserve the original download
  destination and preserve the local credential file during `logout`.

All output is machine-readable JSON. Errors are written to stderr and contain
the Broker request ID when available.
