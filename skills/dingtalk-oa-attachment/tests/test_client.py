import hashlib
import http.client
import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import urllib.parse
import urllib.error
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator, Optional

import pytest


SKILL_ROOT = Path(__file__).resolve().parents[1]
CLIENT_PATH = SKILL_ROOT / "scripts" / "dingtalk_oa_attachment.py"
FIRMWARE_CATEGORY_ID = "category-" + "a" * 52
DEPARTURE_CATEGORY_ID = "category-" + "b" * 52
EXAMPLE_BROKER_URL = "https://broker.example.com"


def load_client_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dingtalk_oa_attachment_client",
        CLIENT_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CLIENT = load_client_module()


class JSONHeaders:
    def get_content_type(self) -> str:
        return "application/json"


class JSONResponse(io.BytesIO):
    headers = JSONHeaders()


class MemoryStore(CLIENT.CredentialStore):
    persistent = True
    name = "memory-test-store"

    def __init__(
        self,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        self.credentials = CLIENT.Credentials(access_token, refresh_token)
        self.saved: list[tuple[str, str]] = []
        self.delete_calls = 0

    def load(self) -> Any:
        return self.credentials

    def save(self, access_token: str, refresh_token: str) -> None:
        self.credentials = CLIENT.Credentials(access_token, refresh_token)
        self.saved.append((access_token, refresh_token))

    def delete(self) -> bool:
        self.delete_calls += 1
        removed = any(
            token is not None
            for token in (
                self.credentials.access_token,
                self.credentials.refresh_token,
            )
        )
        self.credentials = CLIENT.Credentials(None, None)
        return removed


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "Fixture/1.0"

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _problem(self, status: int, code: str) -> None:
        encoded = json.dumps(
            {
                "code": code,
                "detail": f"fixture {status}",
                "requestId": "request-fixture",
            }
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/problem+json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        state = self.server.state
        if self.path == "/api/v1/device-authorizations":
            self._json(
                201,
                {
                    "deviceCode": "device-secret",
                    "userCode": "ABCD-EFGH",
                    "verificationUri": f"{state['origin']}/auth/dingtalk/start",
                    "verificationUriComplete": state["verification_url"],
                    "expiresIn": 600,
                    "interval": 1,
                },
            )
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/v1/device-authorizations/token":
            assert body == {"deviceCode": "device-secret"}
            self._json(
                200,
                {
                    "accessToken": "access-device-secret",
                    "refreshToken": "refresh-device-secret",
                    "tokenType": "Bearer",
                    "expiresIn": 28_800,
                    "refreshExpiresIn": 2_592_000,
                },
            )
            return
        if self.path == "/api/v1/sessions/refresh":
            assert body == {"refreshToken": "refresh-old-secret"}
            refresh_error = state.get("refresh_error")
            if refresh_error is not None:
                status, code = refresh_error
                self._problem(status, code)
                return
            self._json(
                200,
                {
                    "accessToken": "access-new-secret",
                    "refreshToken": "refresh-new-secret",
                    "tokenType": "Bearer",
                    "expiresIn": 28_800,
                    "refreshExpiresIn": 2_592_000,
                },
            )
            return
        self._problem(404, "not_found")

    def do_GET(self) -> None:
        state = self.server.state
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/api/v1/me/approval-categories":
            query = urllib.parse.parse_qs(parsed.query)
            state.setdefault("category_discovery_queries", []).append(query)
            if query.get("cursor") == ["category.cursor"]:
                self._json(
                    200,
                    {
                        "data": {
                            "categories": [
                                {
                                    "id": DEPARTURE_CATEGORY_ID,
                                    "displayName": "Personnel departure",
                                    "directoryName": "Human resources",
                                }
                            ],
                            "complete": True,
                            "scannedPages": 1,
                            "scannedCandidates": 3,
                            "totalCategories": 2,
                        }
                    },
                )
                return
            self._json(
                200,
                {
                    "data": {
                        "categories": [
                            {
                                "id": FIRMWARE_CATEGORY_ID,
                                "displayName": "Firmware flow",
                                "directoryName": "Product engineering",
                            }
                        ],
                        "nextCursor": "category.cursor",
                        "complete": False,
                        "scannedPages": 1,
                        "scannedCandidates": 42,
                        "totalCategories": 2,
                    }
                },
            )
            return
        if parsed.path == "/api/v1/approval-categories":
            self._json(
                200,
                {
                    "data": {
                        "categories": [
                            {
                                "id": FIRMWARE_CATEGORY_ID,
                                "displayName": "Firmware flow",
                                "directoryName": "Product engineering",
                            }
                        ],
                        "complete": True,
                        "scannedPages": 1,
                        "scannedCandidates": 1,
                        "totalCategories": 1,
                    }
                },
            )
            return
        if parsed.path == "/api/v1/me":
            authorization = self.headers.get("Authorization")
            state["authorizations"].append(authorization)
            if authorization not in {
                "Bearer access-new-secret",
                "Bearer access-device-secret",
            }:
                self._problem(401, "unauthorized")
                return
            self._json(
                200,
                {
                    "data": {
                        "corpId": "corp-fixture",
                        "userId": "user-fixture",
                        "unionId": "union-fixture",
                        "displayName": state.get(
                            "display_name",
                            "Fixture User",
                        ),
                    }
                },
            )
            return
        if parsed.path == "/api/v1/approvals":
            state["search_query"] = urllib.parse.parse_qs(parsed.query)
            self._json(
                200,
                {
                    "data": {
                        "categoryId": FIRMWARE_CATEGORY_ID,
                        "items": [
                            {
                                "businessId": "202607171001000374421",
                                "processInstanceId": "process-one",
                                "title": "Firmware release",
                                "attachments": [
                                    {
                                        "fileId": "file-one",
                                        "fileName": "firmware.eml",
                                        "source": "form",
                                    }
                                ],
                            }
                        ],
                        "nextCursor": "signed.cursor",
                    }
                },
            )
            return
        if self.path == "/api/v1/approvals/process-one/attachments":
            authorization = self.headers.get("Authorization")
            state["authorizations"].append(authorization)
            if authorization == "Bearer access-old-secret":
                self._problem(401, "unauthorized")
                return
            if authorization not in {
                "Bearer access-new-secret",
                "Bearer access-device-secret",
            }:
                self._problem(403, "forbidden")
                return
            self._json(
                200,
                {
                    "data": {
                        "processInstanceId": "process-one",
                        "attachments": [
                            {
                                "fileId": "file-one",
                                "fileName": "firmware.eml",
                                "source": "form",
                            }
                        ],
                    }
                },
            )
            return
        if self.path == (
            "/api/v1/approvals/process-one/attachments/file-one/content"
        ):
            if self.headers.get("Authorization") != "Bearer access-new-secret":
                self._problem(403, "forbidden")
                return
            payload = state["attachment"]
            self.send_response(200)
            self.send_header(
                "Content-Type",
                state.get("download_content_type", "application/octet-stream"),
            )
            self.send_header(
                "Content-Length",
                str(state.get("download_content_length", len(payload))),
            )
            self.end_headers()
            self.wfile.write(payload)
            return
        self._problem(404, "not_found")

    def do_DELETE(self) -> None:
        state = self.server.state
        if self.path != "/api/v1/sessions/current":
            self._problem(404, "not_found")
            return
        authorization = self.headers.get("Authorization")
        state["authorizations"].append(authorization)
        delete_error = state.get("delete_error")
        if delete_error is not None:
            status, code = delete_error
            self._problem(status, code)
            return
        if authorization == "Bearer access-old-secret":
            self._problem(401, "unauthorized")
            return
        if authorization not in {
            "Bearer access-new-secret",
            "Bearer access-device-secret",
        }:
            self._problem(403, "forbidden")
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


@contextmanager
def fixture_server() -> Iterator[tuple[str, dict[str, Any]]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    state: dict[str, Any] = {
        "origin": origin,
        "verification_url": (f"{origin}/auth/dingtalk/start?user_code=ABCD-EFGH"),
        "authorizations": [],
        "attachment": b"fixture-attachment-content",
    }
    server.state = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield origin, state
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://broker.example.test/", "https://broker.example.test"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://localhost", "http://localhost"),
        ("https://BROKER.EXAMPLE.TEST:443", "https://broker.example.test"),
        ("http://LOCALHOST:80", "http://localhost"),
    ],
)
def test_validate_broker_url_accepts_secure_origins(
    value: str,
    expected: str,
) -> None:
    assert CLIENT.validate_broker_url(value) == expected


def test_json_credentials_bind_to_canonical_broker_origin(tmp_path: Path) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    first = CLIENT.JsonCredentialStore("https://BROKER.EXAMPLE.TEST:443", credential_file)
    first.save("access-sensitive", "refresh-sensitive")

    second = CLIENT.JsonCredentialStore("https://broker.example.test", credential_file)
    assert second.load() == CLIENT.Credentials("access-sensitive", "refresh-sensitive")


def test_http_error_preserves_bounded_retry_after() -> None:
    body = io.BytesIO(
        json.dumps({"code": "rate_limited", "detail": "retry later"}).encode("utf-8")
    )
    error = urllib.error.HTTPError(
        "https://broker.example.test/api/v1/me",
        429,
        "Too Many Requests",
        {"Retry-After": "60", "X-Request-ID": "request-id"},
        body,
    )

    result = CLIENT._http_client_error(error)

    assert result.retry_after_seconds == 60


@pytest.mark.parametrize(
    "value",
    [
        "",
        "http://broker.example.test",
        "https://user:secret@broker.example.test",
        "https://broker.example.test/api",
        "https://broker.example.test?token=value",
        "https://broker.example.test:bad",
    ],
)
def test_validate_broker_url_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(CLIENT.ClientError):
        CLIENT.validate_broker_url(value)


def test_list_rotates_session_once_and_persists_tokens() -> None:
    with fixture_server() as (origin, state):
        store = MemoryStore("access-old-secret", "refresh-old-secret")
        client = CLIENT.BrokerClient(origin, store)

        response = client.list_attachments("process-one")

    assert response["data"]["attachments"][0]["fileId"] == "file-one"
    assert state["authorizations"] == [
        "Bearer access-old-secret",
        "Bearer access-new-secret",
    ]
    assert store.saved == [("access-new-secret", "refresh-new-secret")]


def test_list_recovers_when_only_refresh_token_is_cached() -> None:
    with fixture_server() as (origin, state):
        store = MemoryStore(None, "refresh-old-secret")
        client = CLIENT.BrokerClient(origin, store)

        response = client.list_attachments("process-one")

    assert response["data"]["attachments"][0]["fileId"] == "file-one"
    assert state["authorizations"] == ["Bearer access-new-secret"]
    assert store.saved == [("access-new-secret", "refresh-new-secret")]


@pytest.mark.parametrize(
    "process_instance_id",
    [
        "PROC-DF836022-D293-44C2-976F-F80EC6340BC8",
        "proc-template-code",
        "process/instance",
        "process instance",
    ],
)
def test_process_instance_id_rejects_template_codes_and_path_data(
    process_instance_id: str,
) -> None:
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        MemoryStore("access", "refresh"),
    )

    with pytest.raises(CLIENT.ClientError):
        client.list_attachments(process_instance_id)


def test_parser_requires_configured_broker_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(CLIENT.BROKER_URL_ENV, raising=False)

    arguments = CLIENT.build_parser().parse_args(["auth-status"])

    assert arguments.broker_url is None
    assert CLIENT.main(["auth-status"]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error["code"] == "missing_broker_url"


def test_categories_and_search_are_broker_backed() -> None:
    with fixture_server() as (origin, state):
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("access-new-secret", "refresh-new-secret"),
        )

        categories = client.list_categories()
        result = client.search_approvals(
            FIRMWARE_CATEGORY_ID,
            keyword="T120",
            created_after="2026-06-01T00:00:00Z",
            created_before="2026-07-01T00:00:00+00:00",
            limit=10,
        )
        first_query = state["search_query"]
        cursor_result = client.search_approvals(
            FIRMWARE_CATEGORY_ID,
            cursor="signed.cursor",
            limit=10,
        )

    assert categories["data"]["categories"][0]["id"] == FIRMWARE_CATEGORY_ID
    assert result["data"]["items"][0]["businessId"] == "202607171001000374421"
    assert result["data"]["items"][0]["processInstanceId"] == "process-one"
    assert cursor_result["data"]["nextCursor"] == "signed.cursor"
    assert first_query == {
        "category": [FIRMWARE_CATEGORY_ID],
        "q": ["T120"],
        "createdAfter": ["2026-06-01T00:00:00Z"],
        "createdBefore": ["2026-07-01T00:00:00+00:00"],
        "limit": ["10"],
    }
    assert state["search_query"] == {
        "category": [FIRMWARE_CATEGORY_ID],
        "cursor": ["signed.cursor"],
        "limit": ["10"],
    }


def test_user_visible_categories_support_cursor_pagination() -> None:
    with fixture_server() as (origin, state):
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("access-new-secret", "refresh-new-secret"),
        )

        first = client.list_my_categories(
            keyword="firmware",
        )
        second = client.list_my_categories(cursor="category.cursor")

    assert first["data"]["categories"][0]["id"] == FIRMWARE_CATEGORY_ID
    assert first["data"]["complete"] is False
    assert second["data"]["categories"][0]["id"] == DEPARTURE_CATEGORY_ID
    assert second["data"]["complete"] is True
    assert state["category_discovery_queries"] == [
        {"q": ["firmware"]},
        {"cursor": ["category.cursor"]},
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        {"category": "Firmware_Flow"},
        {"category": "firmware-flow", "limit": 9},
        {"category": "firmware-flow", "created_after": "2026-07-01"},
        {"category": "firmware-flow", "cursor": "contains whitespace"},
        {"category": "firmware-flow", "keyword": "x" * 101},
        {
            "category": "firmware-flow",
            "created_after": "2026-06-01T00:00:00Z",
            "cursor": "signed.cursor",
        },
        {
            "category": "firmware-flow",
            "created_after": "2026-07-01T00:00:00Z",
            "created_before": "2026-07-01T00:00:00Z",
        },
        {
            "category": "firmware-flow",
            "created_after": "2026-07-02T00:00:00Z",
            "created_before": "2026-07-01T00:00:00Z",
        },
        {
            "category": "firmware-flow",
            "created_after": "2026-01-01T00:00:00Z",
            "created_before": "2026-05-02T00:00:01Z",
        },
    ],
)
def test_search_rejects_invalid_parameters_before_network(
    arguments: dict[str, Any],
) -> None:
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        MemoryStore("access", "refresh"),
    )
    with pytest.raises(CLIENT.ClientError):
        client.search_approvals(**arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        {"keyword": ""},
        {"keyword": "x" * 101},
        {"cursor": "contains whitespace"},
        {"cursor": "signed.cursor", "keyword": "firmware"},
    ],
)
def test_user_category_discovery_rejects_invalid_parameters_before_network(
    arguments: dict[str, Any],
) -> None:
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        MemoryStore("access", "refresh"),
    )
    with pytest.raises(CLIENT.ClientError):
        client.list_my_categories(**arguments)


def test_expired_refresh_token_requires_new_login() -> None:
    with fixture_server() as (origin, state):
        state["refresh_error"] = (401, "unauthorized")
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("access-old-secret", "refresh-old-secret"),
        )

        with pytest.raises(CLIENT.ClientError) as captured:
            client.list_attachments("process-one")

    assert captured.value.code == "reauthentication_required"
    assert captured.value.status == 401
    assert captured.value.request_id == "request-fixture"
    assert state["authorizations"] == ["Bearer access-old-secret"]


def test_stale_refresh_uses_credentials_saved_by_another_process() -> None:
    with fixture_server() as (origin, _):
        store = MemoryStore("access-old-secret", "refresh-old-secret")
        client = CLIENT.BrokerClient(origin, store)

        def stale_refresh(_refresh_token: str) -> dict[str, Any]:
            store.save("access-new-secret", "refresh-new-secret")
            raise CLIENT.ClientError("unauthorized", "stale", status=401)

        client.refresh_session = stale_refresh  # type: ignore[method-assign]
        identity = client.current_identity()

    assert identity["data"]["userId"] == "user-fixture"
    assert store.saved == [("access-new-secret", "refresh-new-secret")]


def test_login_stores_tokens_without_printing_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, _):
        store = MemoryStore()
        client = CLIENT.BrokerClient(origin, store)
        CLIENT.command_login(
            client,
            open_browser=False,
            timeout_seconds=10,
        )

    captured = capsys.readouterr()
    assert "access-device-secret" not in captured.out
    assert "refresh-device-secret" not in captured.out
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert [record["event"] for record in records] == [
        "authorization_required",
        "login_completed",
    ]
    assert records[0]["browserOpenAttempted"] is False
    assert records[0]["browserOpened"] is False
    assert store.saved == [("access-device-secret", "refresh-device-secret")]


def test_login_reports_browser_open_failure_without_aborting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(CLIENT.webbrowser, "open", lambda *_args, **_kwargs: False)
    with fixture_server() as (origin, _):
        store = MemoryStore()
        client = CLIENT.BrokerClient(origin, store)
        CLIENT.command_login(
            client,
            open_browser=True,
            timeout_seconds=10,
        )

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert records[0]["event"] == "authorization_required"
    assert records[0]["browserOpenAttempted"] is True
    assert records[0]["browserOpened"] is False
    assert records[1]["event"] == "login_completed"


def test_login_poll_uses_remaining_login_deadline() -> None:
    observed_timeouts: list[float] = []

    class StalledLoginClient:
        broker_url = "https://broker.example.test"
        store = MemoryStore()
        timeout = 300.0

        @staticmethod
        def create_device_authorization() -> dict[str, Any]:
            return {
                "deviceCode": "device-code",
                "userCode": "ABCD-EFGH",
                "verificationUriComplete": (
                    "https://broker.example.test/auth/dingtalk/start"
                    "?user_code=ABCD-EFGH"
                ),
                "expiresIn": 600,
                "interval": 5,
            }

        @staticmethod
        def exchange_device_code(
            _device_code: str,
            *,
            timeout: float,
        ) -> dict[str, Any]:
            observed_timeouts.append(timeout)
            raise CLIENT.ClientError("upstream_error", "stalled", status=503)

    with pytest.raises(CLIENT.ClientError):
        CLIENT.command_login(
            StalledLoginClient(),
            open_browser=False,
            timeout_seconds=10,
        )

    assert 0 < observed_timeouts[0] <= 10


def test_login_poll_honors_rate_limit_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    class RateLimitedLoginClient:
        broker_url = "https://broker.example.test"
        timeout = 300.0

        def __init__(self) -> None:
            self.store = MemoryStore()
            self.polls = 0

        @staticmethod
        def create_device_authorization() -> dict[str, Any]:
            return {
                "deviceCode": "device-code",
                "userCode": "ABCD-EFGH",
                "verificationUriComplete": (
                    "https://broker.example.test/auth/dingtalk/start"
                    "?user_code=ABCD-EFGH"
                ),
                "expiresIn": 600,
                "interval": 5,
            }

        def exchange_device_code(
            self,
            _device_code: str,
            *,
            timeout: float,
        ) -> dict[str, Any]:
            del timeout
            self.polls += 1
            if self.polls == 1:
                raise CLIENT.ClientError(
                    "rate_limited",
                    "retry",
                    status=429,
                    retry_after_seconds=2,
                )
            return {
                "accessToken": "access-token",
                "refreshToken": "refresh-token",
            }

    monkeypatch.setattr(CLIENT.time, "sleep", sleeps.append)
    client = RateLimitedLoginClient()
    CLIENT.command_login(client, open_browser=False, timeout_seconds=10)

    assert client.polls == 2
    assert sleeps == [2]
    assert client.store.saved == [("access-token", "refresh-token")]


def test_auth_status_validates_identity_without_disclosing_tokens(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, state):
        store = MemoryStore("access-new-secret", "refresh-new-secret")
        client = CLIENT.BrokerClient(origin, store)

        CLIENT.command_auth_status(client)

    output = capsys.readouterr().out
    assert "access-new-secret" not in output
    assert "refresh-new-secret" not in output
    result = json.loads(output)
    assert result == {
        "authenticated": True,
        "brokerUrl": origin,
        "credentialStore": "memory-test-store",
        "data": {
            "corpId": "corp-fixture",
            "displayName": "Fixture User",
            "unionId": "union-fixture",
            "userId": "user-fixture",
        },
        "ok": True,
    }
    assert state["authorizations"] == ["Bearer access-new-secret"]


def test_logout_revokes_session_and_deletes_json_cache_without_disclosing_tokens(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, state):
        credential_file = tmp_path / ".runtime" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-new-secret", "refresh-new-secret")
        client = CLIENT.BrokerClient(origin, store)

        CLIENT.command_logout(client)

    output = capsys.readouterr().out
    assert "access-new-secret" not in output
    assert "refresh-new-secret" not in output
    assert json.loads(output) == {
        "credentialFile": str(credential_file),
        "credentialRemoved": True,
        "credentialStore": "local-json",
        "event": "logout_completed",
        "ok": True,
        "sessionRevoked": True,
    }
    assert state["authorizations"] == ["Bearer access-new-secret"]
    assert not credential_file.exists()


def test_logout_refreshes_expired_access_before_revoking_session(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, state):
        store = MemoryStore("access-old-secret", "refresh-old-secret")
        client = CLIENT.BrokerClient(origin, store)

        CLIENT.command_logout(client)

    result = json.loads(capsys.readouterr().out)
    assert result["sessionRevoked"] is True
    assert result["credentialRemoved"] is True
    assert state["authorizations"] == [
        "Bearer access-old-secret",
        "Bearer access-new-secret",
    ]
    assert store.saved == [("access-new-secret", "refresh-new-secret")]
    assert store.delete_calls == 1
    assert store.load() == CLIENT.Credentials(None, None)


def test_logout_is_idempotent_without_cached_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        CLIENT.JsonCredentialStore("http://127.0.0.1:1", credential_file),
    )

    CLIENT.command_logout(client)

    assert json.loads(capsys.readouterr().out) == {
        "credentialFile": str(credential_file),
        "credentialRemoved": False,
        "credentialStore": "local-json",
        "event": "logout_completed",
        "ok": True,
        "sessionRevoked": False,
    }


def test_logout_removes_cache_when_server_session_is_already_inactive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, state):
        state["refresh_error"] = (401, "unauthorized")
        credential_file = tmp_path / ".runtime" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-old-secret", "refresh-old-secret")
        client = CLIENT.BrokerClient(origin, store)

        CLIENT.command_logout(client)

    result = json.loads(capsys.readouterr().out)
    assert result["sessionRevoked"] is False
    assert result["credentialRemoved"] is True
    assert state["authorizations"] == ["Bearer access-old-secret"]
    assert not credential_file.exists()


def test_logout_preserves_cache_when_revocation_has_transient_failure(
    tmp_path: Path,
) -> None:
    with fixture_server() as (origin, state):
        state["delete_error"] = (503, "upstream_error")
        credential_file = tmp_path / ".runtime" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-new-secret", "refresh-new-secret")
        client = CLIENT.BrokerClient(origin, store)

        with pytest.raises(CLIENT.ClientError) as captured:
            CLIENT.command_logout(client)

    assert captured.value.status == 503
    assert captured.value.request_id == "request-fixture"
    assert credential_file.exists()
    assert store.load() == CLIENT.Credentials(
        "access-new-secret",
        "refresh-new-secret",
    )


def test_login_requires_persistent_credential_store() -> None:
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        CLIENT.CredentialStore(),
    )
    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT.command_login(
            client,
            open_browser=False,
            timeout_seconds=10,
        )
    assert captured.value.code == "credential_store_unavailable"


def test_logout_requires_persistent_credential_store() -> None:
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        CLIENT.CredentialStore(),
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT.command_logout(client)

    assert captured.value.code == "credential_store_unavailable"


def test_login_rejects_cross_origin_verification_url() -> None:
    with fixture_server() as (origin, state):
        state["verification_url"] = (
            "https://attacker.example.test/auth/dingtalk/start?user_code=ABCD-EFGH"
        )
        client = CLIENT.BrokerClient(origin, MemoryStore())
        with pytest.raises(CLIENT.ClientError) as captured:
            CLIENT.command_login(
                client,
                open_browser=False,
                timeout_seconds=10,
            )
    assert captured.value.code == "invalid_response"


@pytest.mark.parametrize(
    ("broker_url", "verification_url"),
    [
        (
            "https://BROKER.EXAMPLE",
            "https://broker.example/auth/dingtalk/start?user_code=ABCD-EFGH",
        ),
        (
            "https://broker.example:443",
            "https://broker.example/auth/dingtalk/start?user_code=ABCD-EFGH",
        ),
        (
            "https://broker.example",
            "https://broker.example:443/auth/dingtalk/start?user_code=ABCD-EFGH",
        ),
        (
            "http://LOCALHOST:80",
            "http://localhost/auth/dingtalk/start?user_code=ABCD-EFGH",
        ),
    ],
)
def test_verification_url_accepts_equivalent_origin_spellings(
    broker_url: str,
    verification_url: str,
) -> None:
    assert CLIENT._validate_verification_url(verification_url, broker_url) == verification_url


def test_verification_url_rejects_different_effective_port() -> None:
    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT._validate_verification_url(
            "https://broker.example/auth/dingtalk/start?user_code=ABCD-EFGH",
            "https://broker.example:8443",
        )

    assert captured.value.code == "invalid_response"


def test_download_is_atomic_private_and_reports_sha256(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, state):
        store = MemoryStore("access-new-secret", "refresh-new-secret")
        client = CLIENT.BrokerClient(origin, store)
        destination = tmp_path / "firmware.eml"

        CLIENT.command_download(
            client,
            "process-one",
            "file-one",
            destination,
            overwrite=False,
        )

    result = json.loads(capsys.readouterr().out)
    assert destination.read_bytes() == state["attachment"]
    assert destination.stat().st_mode & 0o777 == 0o600
    assert result == {
        "bytes": len(state["attachment"]),
        "ok": True,
        "path": str(destination),
        "sha256": hashlib.sha256(state["attachment"]).hexdigest(),
    }
    assert list(tmp_path.glob("*.partial")) == []


@pytest.mark.parametrize(
    ("state_key", "state_value", "expected_code"),
    [
        ("download_content_type", "application/json", "invalid_response"),
        ("download_content_length", 1000, "download_incomplete"),
    ],
)
def test_download_rejects_invalid_stream_and_cleans_temporary_file(
    tmp_path: Path,
    state_key: str,
    state_value: Any,
    expected_code: str,
) -> None:
    with fixture_server() as (origin, state):
        state[state_key] = state_value
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("access-new-secret", "refresh-new-secret"),
        )
        destination = tmp_path / "invalid.bin"
        with pytest.raises(CLIENT.ClientError) as captured:
            CLIENT.command_download(
                client,
                "process-one",
                "file-one",
                destination,
                overwrite=False,
            )

    assert captured.value.code == expected_code
    assert not destination.exists()
    assert list(tmp_path.glob("*.partial")) == []


def test_download_rejects_interrupted_unknown_length_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BinaryHeaders:
        def get_content_type(self) -> str:
            return "application/octet-stream"

        def get(self, name: str) -> None:
            del name
            return None

    class InterruptedResponse:
        headers = BinaryHeaders()

        def __init__(self) -> None:
            self.reads = 0

        def __enter__(self) -> "InterruptedResponse":
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def read(self, size: int) -> bytes:
            del size
            self.reads += 1
            if self.reads == 1:
                return b"partial"
            raise http.client.IncompleteRead(b"")

    client = CLIENT.BrokerClient(
        "https://broker.example.test",
        MemoryStore("access-new-secret", "refresh-new-secret"),
    )
    monkeypatch.setattr(client, "open_download", lambda *_: InterruptedResponse())
    destination = tmp_path / "interrupted.bin"

    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT.command_download(
            client,
            "process-one",
            "file-one",
            destination,
            overwrite=False,
        )

    assert captured.value.code == "download_failed"
    assert not destination.exists()
    assert list(tmp_path.glob("*.partial")) == []


def test_download_refuses_overwrite_without_contacting_broker(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"preserve-me")
    client = CLIENT.BrokerClient(
        "http://127.0.0.1:1",
        MemoryStore("access", "refresh"),
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT.command_download(
            client,
            "process",
            "file",
            destination,
            overwrite=False,
        )

    assert captured.value.code == "output_exists"
    assert destination.read_bytes() == b"preserve-me"


def test_download_uses_windows_atomic_no_clobber_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rename_calls: list[tuple[Path, Path]] = []
    real_rename = CLIENT.os.rename

    def tracked_rename(source: Path, destination: Path) -> None:
        rename_calls.append((source, destination))
        real_rename(source, destination)

    monkeypatch.setattr(CLIENT, "IS_WINDOWS", True)
    monkeypatch.setattr(CLIENT.os, "rename", tracked_rename)

    with fixture_server() as (origin, state):
        destination = tmp_path / "firmware.eml"
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("access-new-secret", "refresh-new-secret"),
        )

        CLIENT.command_download(
            client,
            "process-one",
            "file-one",
            destination,
            overwrite=False,
        )

    assert destination.read_bytes() == state["attachment"]
    assert len(rename_calls) == 1
    assert rename_calls[0][1] == destination
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_download_does_not_apply_posix_mode_on_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real_rename = CLIENT.os.rename

    def fail_chmod(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("POSIX chmod must not run on Windows")

    monkeypatch.setattr(CLIENT, "IS_WINDOWS", True)
    monkeypatch.setattr(CLIENT.os, "chmod", fail_chmod)
    monkeypatch.setattr(CLIENT.os, "rename", real_rename)

    with fixture_server() as (origin, state):
        destination = tmp_path / "firmware.eml"
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("access-new-secret", "refresh-new-secret"),
        )

        CLIENT.command_download(
            client,
            "process-one",
            "file-one",
            destination,
            overwrite=False,
        )

    assert destination.read_bytes() == state["attachment"]
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_json_credentials_round_trip_in_private_file(tmp_path: Path) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    assert store.load() == CLIENT.Credentials(None, None)

    store.save("access-sensitive", "refresh-sensitive")

    assert store.load() == CLIENT.Credentials(
        "access-sensitive",
        "refresh-sensitive",
    )
    assert json.loads(credential_file.read_text(encoding="utf-8")) == {
        "accessToken": "access-sensitive",
        "brokerUrl": "https://broker.example.test",
        "refreshToken": "refresh-sensitive",
        "version": 1,
    }
    if os.name != "nt":
        assert credential_file.parent.stat().st_mode & 0o777 == 0o700
        assert credential_file.stat().st_mode & 0o777 == 0o600
    assert list(credential_file.parent.glob("*.partial")) == []

    assert store.delete() is True
    assert not credential_file.exists()
    assert store.delete() is False


def test_json_credentials_delete_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("preserve", encoding="utf-8")
    credential_file = tmp_path / ".runtime" / "auth.json"
    credential_file.parent.mkdir()
    credential_file.symlink_to(target)
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.delete()

    assert captured.value.code == "credential_store_error"
    assert target.read_text(encoding="utf-8") == "preserve"
    assert credential_file.is_symlink()


def test_json_credentials_delete_rejects_symbolic_link_parent(
    tmp_path: Path,
) -> None:
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    target_file = target_directory / "auth.json"
    target_file.write_text("preserve", encoding="utf-8")
    runtime_directory = tmp_path / ".runtime"
    try:
        runtime_directory.symlink_to(target_directory, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symbolic links are unavailable.")
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        runtime_directory / "auth.json",
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.delete()

    assert captured.value.code == "credential_store_error"
    assert target_file.read_text(encoding="utf-8") == "preserve"


def test_json_credentials_delete_rejects_directory_target(tmp_path: Path) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    credential_file.mkdir(parents=True)
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.delete()

    assert captured.value.code == "credential_store_error"
    assert credential_file.is_dir()


@pytest.mark.parametrize(
    "contents",
    [
        "{",
        json.dumps(
            {
                "version": 2,
                "brokerUrl": "https://broker.example.test",
                "accessToken": "access-sensitive",
                "refreshToken": "refresh-sensitive",
            }
        ),
        json.dumps(
            {
                "version": 1,
                "brokerUrl": "https://other-broker.example.test",
                "accessToken": "access-sensitive",
                "refreshToken": "refresh-sensitive",
            }
        ),
    ],
)
def test_json_credentials_reject_invalid_cache(
    tmp_path: Path,
    contents: str,
) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    credential_file.parent.mkdir()
    credential_file.write_text(contents, encoding="utf-8")
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.load()

    assert captured.value.code == "credential_store_error"


def test_json_credentials_reject_invalid_token_types(tmp_path: Path) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    credential_file.parent.mkdir()
    credential_file.write_text(
        json.dumps(
            {
                "version": 1,
                "brokerUrl": "https://broker.example.test",
                "accessToken": None,
                "refreshToken": "refresh-sensitive",
            }
        ),
        encoding="utf-8",
    )
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.load()

    assert captured.value.code == "credential_store_error"


def test_json_credentials_reject_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    credential_file = tmp_path / ".runtime" / "auth.json"
    credential_file.parent.mkdir()
    credential_file.symlink_to(target)
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.load()

    assert captured.value.code == "credential_store_error"


def test_json_credentials_reject_symbolic_link_parent_on_load(
    tmp_path: Path,
) -> None:
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    credential_file = target_directory / "auth.json"
    credential_file.write_text("{}", encoding="utf-8")
    runtime_directory = tmp_path / ".runtime"
    try:
        runtime_directory.symlink_to(target_directory, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symbolic links are unavailable.")
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        runtime_directory / "auth.json",
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.load()

    assert captured.value.code == "credential_store_error"
    assert "parent must be a real directory" in captured.value.detail


def test_json_credentials_reject_symbolic_link_parent_on_save(
    tmp_path: Path,
) -> None:
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    runtime_directory = tmp_path / ".runtime"
    try:
        runtime_directory.symlink_to(target_directory, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symbolic links are unavailable.")
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        runtime_directory / "auth.json",
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.save("access-sensitive", "refresh-sensitive")

    assert captured.value.code == "credential_store_error"
    assert "parent must be a real directory" in captured.value.detail
    assert not (target_directory / "auth.json").exists()


def test_json_credentials_reject_oversized_cache(tmp_path: Path) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    credential_file.parent.mkdir()
    credential_file.write_bytes(b"x" * (CLIENT.CREDENTIAL_FILE_MAX_BYTES + 1))
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        store.load()

    assert captured.value.code == "credential_store_error"


def test_json_credentials_reject_insecure_unix_permissions(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("Unix permission bits are not authoritative on Windows.")

    credential_file = tmp_path / ".runtime" / "auth.json"
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )
    store.save("access-sensitive", "refresh-sensitive")
    credential_file.chmod(0o644)

    with pytest.raises(CLIENT.ClientError) as captured:
        store.load()

    assert captured.value.code == "credential_store_error"
    assert "insecure permissions" in captured.value.detail


@pytest.mark.parametrize("operation", ["load", "delete", "save"])
def test_json_credentials_reject_writable_unix_parent(
    tmp_path: Path,
    operation: str,
) -> None:
    if os.name == "nt":
        pytest.skip("Unix permission bits are not authoritative on Windows.")

    credential_file = tmp_path / ".runtime" / "auth.json"
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )
    store.save("access-sensitive", "refresh-sensitive")
    credential_file.parent.chmod(0o777)

    with pytest.raises(CLIENT.ClientError) as captured:
        if operation == "save":
            store.save("replacement-access", "replacement-refresh")
        else:
            getattr(store, operation)()

    assert captured.value.code == "credential_store_error"
    assert "parent directory has insecure" in captured.value.detail


def test_json_credentials_clean_partial_file_after_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_file = tmp_path / ".runtime" / "auth.json"
    store = CLIENT.JsonCredentialStore(
        "https://broker.example.test",
        credential_file,
    )

    def fail_replace(source: Path, destination: Path) -> None:
        del source, destination
        raise OSError("fixture replace failure")

    monkeypatch.setattr(CLIENT.os, "replace", fail_replace)

    with pytest.raises(CLIENT.ClientError) as captured:
        store.save("access-sensitive", "refresh-sensitive")

    assert captured.value.code == "credential_store_error"
    assert not credential_file.exists()
    assert list(credential_file.parent.iterdir()) == []


def test_select_credential_store_uses_skill_runtime_json() -> None:
    store = CLIENT.select_credential_store("https://broker.example.test")

    assert isinstance(store, CLIENT.JsonCredentialStore)
    assert store.path == (CLIENT.SKILL_ROOT / ".runtime" / "auth.json")


def test_select_credential_store_accepts_absolute_per_user_path(
    tmp_path: Path,
) -> None:
    credential_file = tmp_path / "profile" / "auth.json"

    store = CLIENT.select_credential_store(
        "https://broker.example.test",
        credential_file,
    )

    assert isinstance(store, CLIENT.JsonCredentialStore)
    assert store.path == credential_file


def test_select_credential_store_rejects_relative_path() -> None:
    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT.select_credential_store(
            "https://broker.example.test",
            Path("relative/auth.json"),
        )

    assert captured.value.code == "invalid_credential_file"


def test_main_lists_attachments_with_cached_session(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, _):
        store = MemoryStore("access-device-secret", "refresh-device-secret")
        client_type = CLIENT.BrokerClient
        captured_timeout: list[float] = []

        def create_client(
            broker_url: str,
            selected_store: MemoryStore,
            *,
            timeout: float,
        ) -> Any:
            captured_timeout.append(timeout)
            return client_type(broker_url, selected_store, timeout=timeout)

        monkeypatch.setattr(CLIENT, "BrokerClient", create_client)
        monkeypatch.setattr(
            CLIENT,
            "select_credential_store",
            lambda broker_url: store,
        )

        exit_code = CLIENT.main(
            [
                "--broker-url",
                origin,
                "--request-timeout",
                "180",
                "list",
                "--process-instance-id",
                "process-one",
            ]
        )

    assert exit_code == 0
    assert captured_timeout == [180.0]
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["data"]["attachments"][0]["fileId"] == "file-one"


def test_main_rejects_out_of_range_request_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = CLIENT.main(
        [
            "--broker-url",
            "http://127.0.0.1:1",
            "--request-timeout",
            "0",
            "auth-status",
        ]
    )

    assert exit_code == 1
    assert json.loads(capsys.readouterr().err)["code"] == "invalid_request_timeout"


def test_main_my_categories_follows_bounded_pages(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, _):
        store = MemoryStore("access-device-secret", "refresh-device-secret")
        monkeypatch.setattr(
            CLIENT,
            "select_credential_store",
            lambda broker_url: store,
        )

        exit_code = CLIENT.main(
            [
                "--broker-url",
                origin,
                "my-categories",
                "--max-pages",
                "2",
            ]
        )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert [category["id"] for category in result["data"]["categories"]] == [
        FIRMWARE_CATEGORY_ID,
        DEPARTURE_CATEGORY_ID,
    ]
    assert result["data"]["complete"] is True
    assert result["data"]["pagesFetched"] == 2
    assert result["data"]["scannedPages"] == 2
    assert result["data"]["scannedCandidates"] == 45
    assert result["data"]["totalCategories"] == 2


def test_main_my_categories_rejects_cursor_with_filters(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = MemoryStore("access-device-secret", "refresh-device-secret")
    monkeypatch.setattr(
        CLIENT,
        "select_credential_store",
        lambda broker_url: store,
    )

    exit_code = CLIENT.main(
        [
            "--broker-url",
            "http://127.0.0.1:1",
            "my-categories",
            "--cursor",
            "signed.cursor",
            "--q",
            "firmware",
        ]
    )

    assert exit_code == 1
    result = json.loads(capsys.readouterr().err)
    assert result["code"] == "invalid_category_parameters"


def test_main_emits_retry_after_seconds(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_with_rate_limit(client: Any) -> None:
        del client
        raise CLIENT.ClientError(
            "rate_limited",
            "retry later",
            status=429,
            retry_after_seconds=60,
        )

    monkeypatch.setattr(CLIENT, "command_auth_status", fail_with_rate_limit)
    exit_code = CLIENT.main(
        ["--broker-url", "https://broker.example.test", "auth-status"]
    )

    assert exit_code == 1
    assert json.loads(capsys.readouterr().err)["retryAfterSeconds"] == 60


def test_main_auth_status_uses_explicit_credential_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, _):
        credential_file = tmp_path / "profile" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-new-secret", "refresh-new-secret")

        exit_code = CLIENT.main(
            [
                "--broker-url",
                origin,
                "--credential-file",
                str(credential_file),
                "auth-status",
            ]
        )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["authenticated"] is True
    assert result["credentialFile"] == str(credential_file)
    assert result["data"]["userId"] == "user-fixture"


def test_main_logout_uses_explicit_credential_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, _):
        credential_file = tmp_path / "profile" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-new-secret", "refresh-new-secret")

        exit_code = CLIENT.main(
            [
                "--broker-url",
                origin,
                "--credential-file",
                str(credential_file),
                "logout",
            ]
        )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["event"] == "logout_completed"
    assert result["sessionRevoked"] is True
    assert result["credentialRemoved"] is True
    assert result["credentialFile"] == str(credential_file)
    assert not credential_file.exists()


def test_main_auth_status_uses_environment_credential_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with fixture_server() as (origin, _):
        credential_file = tmp_path / "profile" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-new-secret", "refresh-new-secret")
        monkeypatch.setenv(
            CLIENT.CREDENTIAL_FILE_ENV,
            str(credential_file),
        )

        exit_code = CLIENT.main(
            [
                "--broker-url",
                origin,
                "auth-status",
            ]
        )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["credentialFile"] == str(credential_file)
    assert result["data"]["userId"] == "user-fixture"


def test_cli_emits_utf8_json_when_inherited_stdout_encoding_is_gbk(
    tmp_path: Path,
) -> None:
    with fixture_server() as (origin, state):
        state["display_name"] = "\u00a0阳尊"
        credential_file = tmp_path / "profile" / "auth.json"
        store = CLIENT.JsonCredentialStore(origin, credential_file)
        store.save("access-new-secret", "refresh-new-secret")
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "gbk"
        environment.pop("PYTHONUTF8", None)

        result = subprocess.run(
            [
                sys.executable,
                str(CLIENT_PATH),
                "--broker-url",
                origin,
                "--credential-file",
                str(credential_file),
                "auth-status",
            ],
            check=False,
            capture_output=True,
            env=environment,
        )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    payload = json.loads(result.stdout.decode("utf-8"))
    assert payload["data"]["displayName"] == "\u00a0阳尊"


def test_main_reports_reauthentication_for_empty_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = CLIENT.JsonCredentialStore(
        "http://127.0.0.1:1",
        tmp_path / ".runtime" / "auth.json",
    )
    monkeypatch.setattr(
        CLIENT,
        "select_credential_store",
        lambda broker_url: store,
    )

    exit_code = CLIENT.main(
        [
            "--broker-url",
            "http://127.0.0.1:1",
            "list",
            "--process-instance-id",
            "process-one",
        ]
    )

    assert exit_code == 1
    error = json.loads(capsys.readouterr().err)
    assert error["code"] == "reauthentication_required"


def test_http_problem_preserves_safe_request_id() -> None:
    with fixture_server() as (origin, _):
        client = CLIENT.BrokerClient(
            origin,
            MemoryStore("denied-secret", "refresh-secret"),
        )
        with pytest.raises(CLIENT.ClientError) as captured:
            client.list_attachments("process-one")

    assert captured.value.status == 403
    assert captured.value.code == "forbidden"
    assert captured.value.request_id == "request-fixture"


def test_json_response_accepts_payload_larger_than_error_limit() -> None:
    response = JSONResponse(
        json.dumps({"data": "x" * CLIENT.MAX_ERROR_BYTES}).encode("utf-8")
    )

    payload = CLIENT._decode_json_response(response)

    assert len(payload["data"]) == CLIENT.MAX_ERROR_BYTES


def test_json_response_rejects_payload_over_size_limit() -> None:
    response = JSONResponse(
        json.dumps({"data": "x" * CLIENT.MAX_JSON_RESPONSE_BYTES}).encode("utf-8")
    )

    with pytest.raises(CLIENT.ClientError) as captured:
        CLIENT._decode_json_response(response)

    assert captured.value.code == "invalid_response"
    assert captured.value.detail == "Broker JSON response is too large."


def test_prompt_preserves_approval_selection_guardrails() -> None:
    prompt = (SKILL_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")

    for required_term in (
        CLIENT.BROKER_URL_ENV,
        "businessId",
        "createTime",
        "title",
        "processInstanceId",
        "fileId",
        "AppSecret",
        "nextCursor",
        "429",
        "logout",
        "no-overwrite",
    ):
        assert required_term in prompt


def test_documentation_covers_cross_platform_credential_management() -> None:
    skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    maintenance = (
        SKILL_ROOT
        / "references"
        / "platform-and-credential-maintenance.md"
    ).read_text(encoding="utf-8")

    for required_term in (
        CLIENT.BROKER_URL_ENV,
        "DINGTALK_OA_CREDENTIAL_FILE",
        "auth-status",
        "browserOpened",
        "logout",
        "%LOCALAPPDATA%",
    ):
        assert required_term in skill
    for required_term in (
        "Windows 10/11",
        EXAMPLE_BROKER_URL,
        "logout",
        "local JSON",
        "source of truth",
        "credential_store_error",
    ):
        assert required_term in maintenance


def test_public_skill_has_no_vendor_broker_default() -> None:
    files = (
        SKILL_ROOT / "SKILL.md",
        SKILL_ROOT / "agents" / "openai.yaml",
        SKILL_ROOT / "scripts" / "dingtalk_oa_attachment.py",
        SKILL_ROOT / "references" / "platform-and-credential-maintenance.md",
    )
    legacy_vendor = "cp" + "innov"

    for path in files:
        content = path.read_text(encoding="utf-8")
        assert legacy_vendor not in content.lower()
        assert "DEFAULT_BROKER_URL" not in content
