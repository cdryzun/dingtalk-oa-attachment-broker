# Authorization Matrix

## Default-deny policy

Authentication and authorization are separate decisions. A valid broker token
does not grant access to arbitrary approvals.

| Identity relationship | Search metadata | List metadata | Download content |
| --- | --- | --- | --- |
| Approval originator | Allow | Allow | Allow |
| Approval approver | Allow | Allow | Allow |
| Approval task user | Allow | Allow | Allow |
| Approval CC user | Allow | Allow | Allow |
| Operation-record CC user | Allow | Allow | Allow |
| Deployment-configured audit administrator | Allow | Allow | Allow |
| Authenticated but unrelated enterprise user | Exclude | Deny | Deny |
| User from another `corpId` | Reject login | Reject login | Reject login |
| Unmapped `unionId` | Reject login | Reject login | Reject login |
| Unknown approval participation | Exclude | Deny | Deny |
| `fileId` missing from approval | N/A | N/A | Deny as not found |

Search never trusts a category match as authorization. Every candidate is
re-fetched and checked using the same participant and administrator policy
before its title, business ID, status, or attachments are returned.

## Administrator control

Administrator user IDs are supplied through the deployment-controlled
`DINGTALK_ADMIN_USER_IDS` environment variable. Version 1 has no runtime
role-management API.

Every change must:

1. identify each enterprise `userId`;
2. explain the audit need in the reviewed change;
3. receive an authorization-owner review;
4. deploy through the normal controlled release path;
5. verify an audit event for a non-sensitive test request.

Do not use nicknames, phone numbers, email addresses, or broad enterprise
membership as authorization substitutes.

## Attachment membership

The broker parses attachment metadata from:

- approval form component `value`;
- approval form component `extValue`;
- operation-record and comment attachments.

Before every download, the broker re-fetches the approval and performs an exact
`fileId` membership check. The client cannot supply a different `spaceId` or a
signed URL.

## Audit decisions

Each returned search result, current-user category discovery candidate, denied
candidate, list authorization, or download authorization records:

- enterprise actor `userId`;
- action;
- `processInstanceId`;
- `fileId`, when applicable;
- allowed or denied decision;
- request ID;
- stable upstream error category;
- creation time.

Audit storage excludes all raw tokens, OAuth codes, URL signatures, form
content, and attachment content.
