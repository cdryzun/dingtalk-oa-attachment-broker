# Contributing

Contributions that improve the self-hosted Broker, DingTalk compatibility,
security controls, documentation, or the bundled Skill are welcome.

## Development

Use Go 1.25 or newer, PostgreSQL 14 or newer, and Python 3.9 or newer for Skill
changes. Configure only development credentials and non-sensitive test
approvals. Never use production credentials on a workstation or include real
approval data in tests, logs, issues, or pull requests.

Run the Go checks before opening a pull request:

```bash
gofmt -w cmd internal
go mod tidy
go mod verify
go vet ./...
go test -race -count=1 -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

Run the Skill checks when changing `skills/dingtalk-oa-attachment`:

```bash
python3 -m pip install "pytest>=8.0" "pytest-cov>=5.0"
python3 -m pytest -q \
  skills/dingtalk-oa-attachment/tests/test_client.py \
  --cov=dingtalk_oa_attachment_client \
  --cov-report=term-missing \
  --cov-fail-under=80
python3 -m py_compile \
  skills/dingtalk-oa-attachment/scripts/dingtalk_oa_attachment.py
```

Documentation and OpenAPI checks use the pinned versions in `.github/workflows/ci.yml`.

## Pull Requests

Create a focused branch and use a Conventional Commit title. Add a regression
test for every bug fix and tests for new behavior. Keep the API, OpenAPI
contract, Skill instructions, and Python client aligned when changing a public
endpoint or response.

Explain security consequences, migration compatibility, and operational impact
in the pull request. The project rejects changes that broaden authorization,
return signed download URLs, persist attachment content, or add OA mutation
operations without an explicit design and threat-model review.

## Security Reports

Do not disclose vulnerabilities in a public issue or pull request. Follow
[SECURITY.md](SECURITY.md).
