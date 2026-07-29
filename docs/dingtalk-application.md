# DingTalk Application Setup

## Application type

Use an enterprise internal application owned by the target DingTalk
organization. Record the application owner, security reviewer, and operational
contact before enabling shared access.

The broker uses the official Go SDK at version `v1.7.41` for current OpenAPI
calls. The union ID mapping call uses the official legacy OAPI endpoint because
that is the documented enterprise `userId` mapping API.

## Callback URLs

Register this exact HTTPS callback:

`https://broker.example.com/auth/dingtalk/callback`

Replace `https://broker.example.com` with the deployment's exact
`PUBLIC_BASE_URL`.

Do not register wildcard callbacks. Deployment is blocked until the
callback performs a complete login and returns the expected `corpId`.

## Required API capabilities

DingTalk console permission labels can change. Select the permission recommended
by the console for each exact API and verify it through DingTalk API debugging.
All rows are mandatory.

Grant `Workflow.Form.Read` for the user-visible form catalog.

| Capability | Credential | Acceptance |
| --- | --- | --- |
| Exchange authorization code | Client credentials | User token and `corpId` |
| Read current user | User token | Non-empty `unionId` |
| Map enterprise identity | App token | Enterprise `userId` |
| List visible forms | App token | Template metadata and pagination |
| List approval instance IDs | App token | Bounded IDs and next token |
| Read approval instance | App token | Participants and attachments |
| Grant attachment download | App token | Matching file and HTTPS URL |

Exact APIs:

```text
POST /v1.0/oauth2/userAccessToken
GET  /v1.0/contact/users/me
POST /topapi/user/getbyunionid
GET  /v1.0/workflow/processes/userVisibilities/templates
POST /v1.0/workflow/processes/instanceIds/query
GET  /v1.0/workflow/processInstances
POST /v1.0/workflow/processInstances/spaces/files/urls/download
```

Official references:

- [DingTalk user token](https://open.dingtalk.com/document/orgapp-server/obtain-user-token)
- [Union ID to user ID API](https://developer.alibaba.com/docs/api.htm?apiId=52234)
- [User-visible approval forms](https://open.dingtalk.com/document/orgapp/obtains-a-list-of-approval-forms-visible-to-the-specified)
- [Approval instance details](https://open.dingtalk.com/document/development/obtains-the-details-of-a-single-approval-instance-pop)
- [Approval attachment download](https://open.dingtalk.com/document/development/download-an-approval-attachment)

The application must not receive OA mutation permissions for this service.

## Verification checklist

Before development acceptance:

- confirm Client ID and secret are injected from a Kubernetes Secret;
- confirm OAuth returns the configured enterprise `corpId`;
- confirm the current user has both `unionId` and mapped `userId`;
- confirm a dedicated non-sensitive test approval can be read by
  `processInstanceId`;
- confirm two users with different DingTalk form visibility receive different
  opaque catalogs and no raw process codes;
- confirm one returned category can list IDs for a bounded test window;
- confirm one form attachment or comment attachment can be granted;
- confirm the grant returns the requested `fileId` and an HTTPS URL.

Stop rollout if any capability is unavailable. Do not fall back to nickname,
phone number, visible approval number scanning, or enterprise-wide access.
