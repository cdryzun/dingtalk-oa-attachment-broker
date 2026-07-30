# DingTalk Application Setup

## 1. Create an enterprise internal application

1. Sign in to the
   [DingTalk Developer Console](https://open-dev.dingtalk.com/).
2. Select the enterprise that will own the Broker deployment.
3. Create an enterprise internal application for this Broker.
4. Record its Client ID, Client Secret, and enterprise Corp ID.
5. Record the application owner, security reviewer, and operational contact.

Use a dedicated application. Do not reuse an application that grants unrelated
business, messaging, address-book, or approval mutation capabilities.

The Broker uses the official Go SDK at version `v1.7.41` for current OpenAPI
calls. The union ID mapping call uses the official legacy OAPI endpoint because
that is the documented enterprise `userId` mapping API.

## 2. Provide a public HTTPS origin

DingTalk must be able to reach the Broker from the public internet. Set
`PUBLIC_BASE_URL` to the externally reachable HTTPS origin, for example:

```text
https://broker.example.com
```

The origin must meet all of these requirements:

- public DNS resolves to the deployed reverse proxy or Broker;
- the TLS certificate is trusted and matches the hostname;
- no VPN, private ingress, login wall, or IP allowlist blocks DingTalk;
- the reverse proxy forwards the callback path to the Broker unchanged;
- the address is stable for the lifetime of an authorization flow.

Loopback, private-network, and temporary tunnel addresses are unsuitable for a
production callback. The Client Secret remains on the Broker and must never be
sent to an Agent or CLI client.

## 3. Register the login callback

In the application details, open the login and sharing capability. Under
**Access Login** (`接入登录`), enter this exact URL in **Callback Domain**
(`回调域名`) and select **Add** (`添加`):

```text
https://broker.example.com/auth/dingtalk/callback
```

Replace `https://broker.example.com` with the exact configured
`PUBLIC_BASE_URL`. The scheme, hostname, and effective port must match. Do not
register a wildcard or a different path.

After saving the callback, publish a new application version in the DingTalk
Developer Console. Permission and callback changes do not take effect until the
application version is published.

Verify public routing before testing login:

```bash
PUBLIC_BASE_URL="https://broker.example.com"

curl --fail --silent "$PUBLIC_BASE_URL/healthz"
curl --silent --output /dev/null --write-out '%{http_code}\n' \
  "$PUBLIC_BASE_URL/auth/dingtalk/callback"
```

The health check must return `200`. A callback request without OAuth parameters
must reach the Broker and return `400`; DNS, TLS, proxy, or network failures mean
the callback is not ready.

A successful browser authorization ends on the Broker confirmation page. The
browser can then return to the requesting Agent or CLI client.

![Successful DingTalk authorization callback](images/authorization-complete.png)

The published image is cropped to exclude the callback URL, OAuth code, state,
hostname, and browser profile data.

## 4. Grant the required permissions

Open the application's permission management page. Search by permission code
because translated console labels can change. Grant every permission below.

| Console capability | Permission code | Broker use |
| --- | --- | --- |
| Personal contact read | `Contact.User.Read` | Read current `unionId` |
| Member information read | `qyapi_get_member` | Map `unionId` to `userId` |
| Workflow form read | `Workflow.Form.Read` | List user-visible forms |
| Workflow instance read | `Workflow.Instance.Read` | Read IDs and details |
| Workflow instance write | `Workflow.Instance.Write` | Grant file download |
| User credential base | `open_app_api_base` | Exchange authorization code |
| Enterprise API base | `qyapi_base` | Obtain the app token |

`qyapi_base` is normally enabled by default. The console may also display
`snsapi_base` as a default permission; the Broker does not call SNS APIs and
does not depend on that permission.

DingTalk currently places the API that grants an approval attachment download
URL under `Workflow.Instance.Write`. The Broker uses that scope only for
`POST /v1.0/workflow/processInstances/spaces/files/urls/download`. It does not
create, approve, reject, update, or revoke approval instances. Treat the Client
Secret as privileged because the DingTalk scope is broader than the Broker's
read-only behavior.

Do not grant permissions that the Broker does not use. In particular,
`qyapi_get_member_by_mobile` and `qyapi_aflow` are not required. Do not add other
OA mutation, messaging, or enterprise-wide address-book scopes.

## 5. Verify the exact API calls

The granted permissions must allow these calls:

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

## 6. Acceptance checklist

Before production rollout:

- confirm the deployed callback is publicly reachable over trusted HTTPS;
- confirm the published callback exactly matches `PUBLIC_BASE_URL` plus
  `/auth/dingtalk/callback`;
- confirm Client ID and Client Secret are injected from a secret store;
- confirm OAuth returns the configured enterprise `corpId`;
- confirm the current user has both `unionId` and mapped `userId`;
- confirm a dedicated non-sensitive test approval can be read by
  `processInstanceId`;
- confirm two users with different form visibility receive different opaque
  catalogs and no raw process codes;
- confirm one returned category can list IDs for a bounded test window;
- confirm one form or comment attachment can be granted;
- confirm the grant returns the requested `fileId` and an HTTPS URL.

Stop rollout if any required capability is unavailable. Do not fall back to
nickname, phone number, visible approval number scanning, or enterprise-wide
access.
