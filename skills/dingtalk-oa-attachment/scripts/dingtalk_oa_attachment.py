#!/usr/bin/env python3
"""Secure CLI for the DingTalk OA Attachment Broker."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Mapping, Optional, Tuple


BROKER_URL_ENV = "DINGTALK_OA_BROKER_URL"
CREDENTIAL_FILE_ENV = "DINGTALK_OA_CREDENTIAL_FILE"
SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CREDENTIAL_FILE = SKILL_ROOT / ".runtime" / "auth.json"
CREDENTIAL_FILE_VERSION = 1
CREDENTIAL_FILE_MAX_BYTES = 16_384
MAX_ERROR_BYTES = 65_536
MAX_JSON_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_KEYWORD_CHARACTERS = 100
MAX_CATEGORY_DISCOVERY_PAGES = 100
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_RETRY_AFTER_SECONDS = 3_600
REFRESH_RECOVERY_WAIT_SECONDS = 1.0
REFRESH_RECOVERY_POLL_SECONDS = 0.05
IS_WINDOWS = os.name == "nt"


class ClientError(Exception):
    """A safe, user-facing client error."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        status: Optional[int] = None,
        request_id: Optional[str] = None,
        retry_after_seconds: Optional[int] = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status
        self.request_id = request_id
        self.retry_after_seconds = retry_after_seconds


class StructuredArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ClientError(
            "invalid_arguments",
            "Command-line arguments are invalid.",
        )


@dataclass(frozen=True)
class Credentials:
    access_token: Optional[str]
    refresh_token: Optional[str]


class CredentialStore:
    """Credential persistence contract."""

    persistent = False
    name = "environment"

    def load(self) -> Credentials:
        raise NotImplementedError

    def save(self, access_token: str, refresh_token: str) -> None:
        raise ClientError(
            "credential_store_unavailable",
            "Login requires a writable local credential cache.",
        )

    def delete(self) -> bool:
        raise ClientError(
            "credential_store_unavailable",
            "Logout requires a writable local credential cache.",
        )


class JsonCredentialStore(CredentialStore):
    """Local JSON credential cache scoped to one Broker origin."""

    persistent = True
    name = "local-json"

    def __init__(
        self,
        broker_url: str,
        path: Path = DEFAULT_CREDENTIAL_FILE,
    ) -> None:
        self.broker_url = validate_broker_url(broker_url)
        self.path = path

    def _validate_parent_directory(self) -> None:
        try:
            parent_stat = self.path.parent.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise ClientError(
                "credential_store_error",
                "The local credential cache parent must be a real directory.",
            )
        if not IS_WINDOWS and (
            parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o022
        ):
            raise ClientError(
                "credential_store_error",
                "The local credential cache parent directory has insecure "
                "ownership or permissions.",
            )

    def load(self) -> Credentials:
        try:
            self._validate_parent_directory()
            try:
                file_stat = self.path.lstat()
            except FileNotFoundError:
                return Credentials(None, None)
            if stat.S_ISLNK(file_stat.st_mode):
                raise ClientError(
                    "credential_store_error",
                    "The local credential cache must not be a symbolic link.",
                )
            if not stat.S_ISREG(file_stat.st_mode):
                raise ClientError(
                    "credential_store_error",
                    "The local credential cache must be a regular file.",
                )
            if file_stat.st_size > CREDENTIAL_FILE_MAX_BYTES:
                raise ClientError(
                    "credential_store_error",
                    "The local credential cache is too large.",
                )
            if not IS_WINDOWS:
                if file_stat.st_uid != os.getuid():
                    raise ClientError(
                        "credential_store_error",
                        "The local credential cache is not owned by the current user.",
                    )
                if file_stat.st_mode & 0o077:
                    raise ClientError(
                        "credential_store_error",
                        "The local credential cache has insecure permissions.",
                    )
            with self.path.open("r", encoding="utf-8") as credential_stream:
                payload = json.load(credential_stream)
        except ClientError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ClientError(
                "credential_store_error",
                "The local credential cache could not be read.",
            ) from None

        if (
            not isinstance(payload, dict)
            or payload.get("version") != CREDENTIAL_FILE_VERSION
            or payload.get("brokerUrl") != self.broker_url
        ):
            raise ClientError(
                "credential_store_error",
                "The local credential cache does not match this Broker.",
            )

        access_token = payload.get("accessToken")
        refresh_token = payload.get("refreshToken")
        if not isinstance(access_token, str) or not isinstance(refresh_token, str):
            raise ClientError(
                "credential_store_error",
                "The local credential cache contains invalid tokens.",
            )
        return Credentials(
            _optional_secret(access_token),
            _optional_secret(refresh_token),
        )

    def save(self, access_token: str, refresh_token: str) -> None:
        access = _require_secret(access_token, "access token")
        refresh = _require_secret(refresh_token, "refresh token")
        payload = {
            "accessToken": access,
            "brokerUrl": self.broker_url,
            "refreshToken": refresh,
            "version": CREDENTIAL_FILE_VERSION,
        }
        temporary_path: Optional[Path] = None
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._validate_parent_directory()
            if not IS_WINDOWS:
                os.chmod(self.path.parent, 0o700)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".auth-",
                suffix=".partial",
                dir=self.path.parent,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "w", encoding="utf-8") as credential_stream:
                if not IS_WINDOWS:
                    os.fchmod(credential_stream.fileno(), 0o600)
                json.dump(
                    payload,
                    credential_stream,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                credential_stream.write("\n")
                credential_stream.flush()
                os.fsync(credential_stream.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
            if not IS_WINDOWS:
                os.chmod(self.path, 0o600)
        except ClientError:
            raise
        except OSError:
            raise ClientError(
                "credential_store_error",
                "The local credential cache could not be updated.",
            ) from None
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

    def delete(self) -> bool:
        try:
            self._validate_parent_directory()
            file_stat = self.path.lstat()
        except FileNotFoundError:
            return False
        except ClientError:
            raise
        except OSError:
            raise ClientError(
                "credential_store_error",
                "The local credential cache could not be inspected.",
            ) from None

        if stat.S_ISLNK(file_stat.st_mode):
            raise ClientError(
                "credential_store_error",
                "The local credential cache must not be a symbolic link.",
            )
        if not stat.S_ISREG(file_stat.st_mode):
            raise ClientError(
                "credential_store_error",
                "The local credential cache must be a regular file.",
            )
        if not IS_WINDOWS and file_stat.st_uid != os.getuid():
            raise ClientError(
                "credential_store_error",
                "The local credential cache is not owned by the current user.",
            )
        try:
            self.path.unlink()
        except FileNotFoundError:
            return False
        except OSError:
            raise ClientError(
                "credential_store_error",
                "The local credential cache could not be removed.",
            ) from None
        return True


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent bearer credentials from following redirects."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: BinaryIO,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        del req, fp, code, msg, headers, newurl
        return None


class BrokerClient:
    """Small HTTP client with one bounded session refresh retry."""

    def __init__(
        self,
        broker_url: str,
        store: CredentialStore,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        self.broker_url = validate_broker_url(broker_url)
        self.store = store
        self.timeout = _validate_request_timeout(timeout)
        self.opener = opener or urllib.request.build_opener(NoRedirectHandler())

    def create_device_authorization(self) -> Dict[str, Any]:
        return self._json_request("POST", "/api/v1/device-authorizations")

    def exchange_device_code(
        self,
        device_code: str,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        return self._json_request(
            "POST",
            "/api/v1/device-authorizations/token",
            body={"deviceCode": device_code},
            timeout=timeout,
        )

    def refresh_session(self, refresh_token: str) -> Dict[str, Any]:
        return self._json_request(
            "POST",
            "/api/v1/sessions/refresh",
            body={"refreshToken": refresh_token},
        )

    def current_identity(self) -> Dict[str, Any]:
        return self._authenticated_json_request("GET", "/api/v1/me")

    def revoke_current_session(self) -> None:
        response = self._authenticated_open(
            "DELETE",
            "/api/v1/sessions/current",
        )
        with response:
            return

    def list_attachments(self, process_instance_id: str) -> Dict[str, Any]:
        process_instance_id = _validate_process_instance_id(process_instance_id)
        path = (
            "/api/v1/approvals/"
            f"{urllib.parse.quote(process_instance_id, safe='')}/attachments"
        )
        return self._authenticated_json_request("GET", path)

    def list_categories(self) -> Dict[str, Any]:
        return self._authenticated_json_request(
            "GET",
            "/api/v1/approval-categories",
        )

    def list_my_categories(
        self,
        *,
        keyword: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        if cursor is not None and keyword is not None:
            raise ClientError(
                "invalid_category_parameters",
                "Category cursor cannot be combined with a keyword.",
            )
        parameters = []
        if keyword is not None:
            parameters.append(("q", _validate_keyword(keyword)))
        if cursor is not None:
            parameters.append(("cursor", _validate_cursor(cursor)))
        path = "/api/v1/me/approval-categories"
        if parameters:
            path += "?" + urllib.parse.urlencode(parameters)
        return self._authenticated_json_request("GET", path)

    def search_approvals(
        self,
        category: str,
        *,
        keyword: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
        cursor: Optional[str] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        category_id = _validate_category(category)
        if not 10 <= limit <= 20:
            raise ClientError(
                "invalid_limit",
                "Approval search limit must be between 10 and 20.",
            )
        if cursor is not None and (
            keyword is not None
            or created_after is not None
            or created_before is not None
        ):
            raise ClientError(
                "invalid_search_parameters",
                "Approval search cursor cannot be combined with keyword or time bounds.",
            )
        created_after_value, created_before_value = _validate_time_window(
            created_after,
            created_before,
        )
        parameters = [
            ("category", category_id),
            ("limit", str(limit)),
        ]
        if keyword is not None:
            parameters.append(("q", _validate_keyword(keyword)))
        if created_after_value is not None:
            parameters.append(("createdAfter", created_after_value))
        if created_before_value is not None:
            parameters.append(("createdBefore", created_before_value))
        if cursor is not None:
            parameters.append(("cursor", _validate_cursor(cursor)))
        return self._authenticated_json_request(
            "GET",
            "/api/v1/approvals?" + urllib.parse.urlencode(parameters),
        )

    def open_download(
        self,
        process_instance_id: str,
        file_id: str,
    ) -> Any:
        process_instance_id = _validate_process_instance_id(process_instance_id)
        file_id = _validate_identifier(file_id, "fileId")
        path = (
            "/api/v1/approvals/"
            f"{urllib.parse.quote(process_instance_id, safe='')}/attachments/"
            f"{urllib.parse.quote(file_id, safe='')}/content"
        )
        return self._authenticated_open("GET", path)

    def _authenticated_json_request(
        self,
        method: str,
        path: str,
    ) -> Dict[str, Any]:
        response = self._authenticated_open(method, path)
        with response:
            return _decode_json_response(response)

    def _authenticated_open(self, method: str, path: str) -> Any:
        credentials = self.store.load()
        if credentials.access_token:
            try:
                return self._open(
                    method,
                    path,
                    bearer=credentials.access_token,
                )
            except ClientError as error:
                if error.status != 401:
                    raise
                if not self.store.persistent or not credentials.refresh_token:
                    raise
        elif not self.store.persistent or not credentials.refresh_token:
            _require_access_token(credentials.access_token)

        try:
            session = self.refresh_session(credentials.refresh_token)
        except ClientError as error:
            if error.status in {401, 409, 410}:
                deadline = time.monotonic() + REFRESH_RECOVERY_WAIT_SECONDS
                while True:
                    replacement = self.store.load()
                    if replacement != credentials and replacement.access_token:
                        return self._open(
                            method,
                            path,
                            bearer=replacement.access_token,
                        )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(REFRESH_RECOVERY_POLL_SECONDS, remaining))
                raise ClientError(
                    "reauthentication_required",
                    "The Broker session expired; run login again.",
                    status=error.status,
                    request_id=error.request_id,
                ) from None
            raise
        access_token, refresh_token = _session_tokens(session)
        self.store.save(access_token, refresh_token)
        return self._open(method, path, bearer=access_token)

    def _json_request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        response = self._open(method, path, body=body, timeout=timeout)
        with response:
            return _decode_json_response(response)

    def _open(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Dict[str, Any]] = None,
        bearer: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        if not path.startswith("/"):
            raise ClientError("invalid_path", "Broker path must be absolute.")
        encoded_body = None
        headers = {
            "Accept": "application/json, application/problem+json, application/octet-stream",
            "User-Agent": "dingtalk-oa-attachment-skill/1.0",
            "X-Request-ID": str(uuid.uuid4()),
        }
        if body is not None:
            encoded_body = json.dumps(
                body,
                separators=(",", ":"),
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"

        request = urllib.request.Request(
            f"{self.broker_url}{path}",
            data=encoded_body,
            headers=headers,
            method=method,
        )
        try:
            return self.opener.open(
                request,
                timeout=self.timeout if timeout is None else min(self.timeout, timeout),
            )
        except urllib.error.HTTPError as error:
            raise _http_client_error(error) from None
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            UnicodeError,
            OSError,
        ) as error:
            raise ClientError(
                "network_error",
                f"Broker request failed: {type(error).__name__}.",
            ) from None


def validate_broker_url(value: Optional[str]) -> str:
    """Validate and canonicalize the trusted Broker origin."""
    raw = (value or "").strip()
    if not raw:
        raise ClientError(
            "missing_broker_url",
            f"Set {BROKER_URL_ENV} or pass --broker-url.",
        )
    try:
        parsed = urllib.parse.urlsplit(raw)
        hostname = parsed.hostname or ""
        port = parsed.port
        if ":" not in hostname:
            hostname = hostname.encode("idna").decode("ascii")
        hostname = hostname.lower()
    except (UnicodeError, ValueError):
        raise ClientError(
            "invalid_broker_url",
            "Broker URL authority is invalid.",
        ) from None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ClientError(
            "invalid_broker_url",
            "Broker URL must not include credentials, a query, or a fragment.",
        )
    if parsed.path not in ("", "/"):
        raise ClientError(
            "invalid_broker_url",
            "Broker URL must contain only a scheme and authority.",
        )
    loopback = hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ClientError(
            "invalid_broker_url",
            "Broker URL must use HTTPS; HTTP is allowed only for loopback tests.",
        )
    if not hostname or port is not None and not (1 <= port <= 65_535):
        raise ClientError("invalid_broker_url", "Broker URL authority is invalid.")
    default_port = {"http": 80, "https": 443}[parsed.scheme]
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return urllib.parse.urlunsplit((parsed.scheme, authority, "", "", ""))


def select_credential_store(
    broker_url: str,
    credential_file: Optional[Path] = None,
) -> CredentialStore:
    """Use a local JSON credential cache scoped to the current user."""
    path = DEFAULT_CREDENTIAL_FILE
    if credential_file is not None:
        try:
            path = Path(credential_file).expanduser()
        except RuntimeError:
            raise ClientError(
                "invalid_credential_file",
                "The credential file home directory could not be resolved.",
            ) from None
        if not path.is_absolute():
            raise ClientError(
                "invalid_credential_file",
                "The credential file path must be absolute.",
            )
    return JsonCredentialStore(broker_url, path)


def _credential_store_metadata(store: CredentialStore) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"credentialStore": store.name}
    if isinstance(store, JsonCredentialStore):
        metadata["credentialFile"] = str(store.path)
    return metadata


def command_login(
    client: BrokerClient,
    *,
    open_browser: bool,
    timeout_seconds: int,
) -> None:
    if not client.store.persistent:
        raise ClientError(
            "credential_store_unavailable",
            "Login requires a writable local JSON credential cache.",
        )

    authorization = client.create_device_authorization()
    required = (
        "deviceCode",
        "userCode",
        "verificationUriComplete",
        "expiresIn",
        "interval",
    )
    if any(key not in authorization for key in required):
        raise ClientError(
            "invalid_response",
            "Broker returned an incomplete device authorization.",
        )

    verification_url = _validate_verification_url(
        str(authorization["verificationUriComplete"]),
        client.broker_url,
    )
    expires_in = _positive_int(authorization["expiresIn"], "expiresIn")
    interval = _positive_int(authorization["interval"], "interval")
    browser_opened = False
    if open_browser:
        try:
            browser_opened = bool(webbrowser.open(verification_url, new=2))
        except (OSError, webbrowser.Error):
            browser_opened = False
    emit_json(
        {
            "ok": True,
            "event": "authorization_required",
            "userCode": authorization["userCode"],
            "verificationUriComplete": verification_url,
            "expiresIn": expires_in,
            "browserOpenAttempted": open_browser,
            "browserOpened": browser_opened,
            **_credential_store_metadata(client.store),
        }
    )

    deadline = time.monotonic() + min(expires_in, timeout_seconds)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            session = client.exchange_device_code(
                str(authorization["deviceCode"]),
                timeout=min(client.timeout, remaining),
            )
        except ClientError as error:
            if error.status == 428:
                time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
                continue
            if error.status == 429 and error.retry_after_seconds is not None:
                retry_delay = error.retry_after_seconds
                remaining = deadline - time.monotonic()
                if 0 < retry_delay <= remaining:
                    time.sleep(retry_delay)
                    continue
            if error.status == 503:
                remaining = deadline - time.monotonic()
                if interval <= remaining:
                    time.sleep(interval)
                    continue
            raise
        access_token, refresh_token = _session_tokens(session)
        client.store.save(access_token, refresh_token)
        emit_json(
            {
                "ok": True,
                "event": "login_completed",
                "tokenType": session.get("tokenType", "Bearer"),
                "expiresIn": session.get("expiresIn"),
                "refreshExpiresIn": session.get("refreshExpiresIn"),
                **_credential_store_metadata(client.store),
            }
        )
        return

    raise ClientError(
        "authorization_timeout",
        "Device authorization did not complete before the timeout.",
    )


def command_auth_status(client: BrokerClient) -> None:
    response = client.current_identity()
    data = response.get("data")
    required_fields = ("corpId", "userId", "unionId", "displayName")
    if not isinstance(data, dict) or any(
        not isinstance(data.get(field), str) for field in required_fields
    ):
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid current identity.",
        )
    emit_json(
        {
            "ok": True,
            "authenticated": True,
            "brokerUrl": client.broker_url,
            "data": data,
            **_credential_store_metadata(client.store),
        }
    )


def command_logout(client: BrokerClient) -> None:
    if not client.store.persistent:
        raise ClientError(
            "credential_store_unavailable",
            "Logout requires a writable local JSON credential cache.",
        )

    credentials = client.store.load()
    session_revoked = False
    if credentials.access_token or credentials.refresh_token:
        try:
            client.revoke_current_session()
            session_revoked = True
        except ClientError as error:
            if (
                error.code != "reauthentication_required"
                and error.status not in {401, 409, 410}
            ):
                raise

    credential_removed = client.store.delete()
    emit_json(
        {
            "ok": True,
            "event": "logout_completed",
            "sessionRevoked": session_revoked,
            "credentialRemoved": credential_removed,
            **_credential_store_metadata(client.store),
        }
    )


def command_list(client: BrokerClient, process_instance_id: str) -> None:
    response = client.list_attachments(process_instance_id)
    data = response.get("data")
    if not isinstance(data, dict):
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid attachment list.",
        )
    emit_json({"ok": True, "data": data})


def command_categories(client: BrokerClient) -> None:
    response = client.list_categories()
    data = response.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("categories"), list):
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid approval category list.",
        )
    emit_json({"ok": True, "data": data})


def command_my_categories(
    client: BrokerClient,
    *,
    keyword: Optional[str],
    cursor: Optional[str],
    max_pages: int,
    all_pages: bool,
) -> None:
    if not 1 <= max_pages <= MAX_CATEGORY_DISCOVERY_PAGES:
        raise ClientError(
            "invalid_max_pages",
            f"max-pages must be between 1 and {MAX_CATEGORY_DISCOVERY_PAGES}.",
        )
    if cursor is not None and keyword is not None:
        raise ClientError(
            "invalid_category_parameters",
            "Category cursor cannot be combined with a keyword.",
        )
    page_limit = MAX_CATEGORY_DISCOVERY_PAGES if all_pages else max_pages
    categories: list[Dict[str, Any]] = []
    category_ids: set[str] = set()
    next_cursor = cursor
    seen_cursors: set[str] = set()
    total_scanned_candidates = 0
    total_scanned_pages = 0
    total_categories: Optional[int] = None
    complete = False
    pages_fetched = 0

    while pages_fetched < page_limit:
        response = client.list_my_categories(
            keyword=keyword if pages_fetched == 0 and cursor is None else None,
            cursor=next_cursor,
        )
        data = response.get("data")
        if not isinstance(data, dict):
            raise ClientError(
                "invalid_response",
                "Broker returned an invalid user-visible category result.",
            )
        page_categories = data.get("categories")
        page_complete = data.get("complete")
        scanned_pages = data.get("scannedPages")
        scanned_candidates = data.get("scannedCandidates")
        page_total_categories = data.get("totalCategories")
        if (
            not isinstance(page_categories, list)
            or not isinstance(page_complete, bool)
            or not isinstance(scanned_pages, int)
            or isinstance(scanned_pages, bool)
            or scanned_pages < 0
            or not isinstance(scanned_candidates, int)
            or isinstance(scanned_candidates, bool)
            or scanned_candidates < 0
            or not isinstance(page_total_categories, int)
            or isinstance(page_total_categories, bool)
            or page_total_categories < 0
        ):
            raise ClientError(
                "invalid_response",
                "Broker returned an invalid user-visible category result.",
            )
        for category in page_categories:
            if not isinstance(category, dict):
                raise ClientError(
                    "invalid_response",
                    "Broker returned an invalid user-visible category.",
                )
            category_id = category.get("id")
            if not isinstance(category_id, str) or not category_id:
                raise ClientError(
                    "invalid_response",
                    "Broker returned an invalid user-visible category.",
                )
            if category_id not in category_ids:
                category_ids.add(category_id)
                categories.append(category)
        total_scanned_pages += scanned_pages
        total_scanned_candidates += scanned_candidates
        if total_categories is None:
            total_categories = page_total_categories
        elif total_categories != page_total_categories:
            raise ClientError(
                "invalid_response",
                "Broker changed the category catalog during pagination.",
            )
        pages_fetched += 1
        complete = page_complete
        candidate_cursor = data.get("nextCursor")
        if complete:
            next_cursor = None
            break
        if not isinstance(candidate_cursor, str) or not candidate_cursor:
            raise ClientError(
                "invalid_response",
                "Broker returned an incomplete category result without a cursor.",
            )
        if candidate_cursor in seen_cursors:
            raise ClientError(
                "invalid_response",
                "Broker repeated a category discovery cursor.",
            )
        seen_cursors.add(candidate_cursor)
        next_cursor = candidate_cursor

    result: Dict[str, Any] = {
        "categories": categories,
        "complete": complete,
        "pagesFetched": pages_fetched,
        "scannedPages": total_scanned_pages,
        "scannedCandidates": total_scanned_candidates,
        "totalCategories": total_categories or 0,
    }
    if not complete and next_cursor is not None:
        result["nextCursor"] = next_cursor
    emit_json({"ok": True, "data": result})


def command_search(
    client: BrokerClient,
    category: str,
    *,
    keyword: Optional[str],
    created_after: Optional[str],
    created_before: Optional[str],
    cursor: Optional[str],
    limit: int,
) -> None:
    response = client.search_approvals(
        category,
        keyword=keyword,
        created_after=created_after,
        created_before=created_before,
        cursor=cursor,
        limit=limit,
    )
    data = response.get("data")
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("categoryId"), str)
        or not isinstance(data.get("items"), list)
    ):
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid approval search result.",
        )
    emit_json({"ok": True, "data": data})


def command_download(
    client: BrokerClient,
    process_instance_id: str,
    file_id: str,
    output: Path,
    *,
    overwrite: bool,
) -> None:
    try:
        destination = output.expanduser().absolute()
    except RuntimeError:
        raise ClientError(
            "invalid_output",
            "The output path home directory could not be resolved.",
        ) from None
    parent = destination.parent
    if not parent.is_dir():
        raise ClientError(
            "invalid_output",
            "The output directory does not exist.",
        )
    if destination.is_dir():
        raise ClientError("invalid_output", "The output path is a directory.")
    if destination.exists() and not overwrite:
        raise ClientError(
            "output_exists",
            "The output file already exists; explicit --overwrite is required.",
        )
    response = client.open_download(process_instance_id, file_id)
    temp_path: Optional[Path] = None
    byte_count = 0
    digest = hashlib.sha256()
    try:
        with response:
            content_type = response.headers.get_content_type()
            if content_type != "application/octet-stream":
                raise ClientError(
                    "invalid_response",
                    "Broker returned an unexpected download content type.",
                )
            expected_length = _content_length(response.headers.get("Content-Length"))
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{destination.name}.",
                suffix=".partial",
                dir=str(parent),
                delete=False,
            ) as temporary:
                temp_path = Path(temporary.name)
                if not IS_WINDOWS:
                    os.chmod(temp_path, 0o600)
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    temporary.write(chunk)
                    digest.update(chunk)
                    byte_count += len(chunk)
                if expected_length is not None and byte_count != expected_length:
                    raise ClientError(
                        "download_incomplete",
                        "Downloaded byte count did not match Content-Length.",
                    )
                temporary.flush()
                os.fsync(temporary.fileno())

        if temp_path is None:
            raise ClientError("download_failed", "No temporary file was created.")
        if overwrite:
            os.replace(temp_path, destination)
        else:
            publish_without_overwrite = os.rename if IS_WINDOWS else os.link
            try:
                publish_without_overwrite(temp_path, destination)
            except FileExistsError:
                raise ClientError(
                    "output_exists",
                    "The output file was created concurrently; it was not replaced.",
                ) from None
            if not IS_WINDOWS:
                temp_path.unlink()
        temp_path = None
        emit_json(
            {
                "ok": True,
                "path": str(destination),
                "bytes": byte_count,
                "sha256": digest.hexdigest(),
            }
        )
    except (OSError, http.client.HTTPException) as error:
        raise ClientError(
            "download_failed",
            f"Download could not be written: {type(error).__name__}.",
        ) from None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _decode_json_response(response: Any) -> Dict[str, Any]:
    content_type = response.headers.get_content_type()
    if content_type not in {"application/json", "application/problem+json"}:
        raise ClientError(
            "invalid_response",
            "Broker returned an unexpected content type.",
        )
    try:
        raw = response.read(MAX_JSON_RESPONSE_BYTES + 1)
        if len(raw) > MAX_JSON_RESPONSE_BYTES:
            raise ClientError(
                "invalid_response",
                "Broker JSON response is too large.",
            )
        payload = json.loads(raw)
    except (OSError, http.client.HTTPException):
        raise ClientError(
            "network_error",
            "Broker response was interrupted.",
        ) from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ClientError("invalid_response", "Broker returned invalid JSON.") from None
    if not isinstance(payload, dict):
        raise ClientError(
            "invalid_response",
            "Broker JSON response must be an object.",
        )
    return payload


def _http_client_error(error: urllib.error.HTTPError) -> ClientError:
    request_id = error.headers.get("X-Request-ID")
    code = f"http_{error.code}"
    detail = f"Broker returned HTTP {error.code}."
    retry_after_seconds: Optional[int] = None
    try:
        candidate_retry_after = int(error.headers.get("Retry-After", ""))
        if 1 <= candidate_retry_after <= MAX_RETRY_AFTER_SECONDS:
            retry_after_seconds = candidate_retry_after
    except (TypeError, ValueError):
        pass
    try:
        raw = error.read(MAX_ERROR_BYTES + 1)
        if len(raw) <= MAX_ERROR_BYTES:
            problem = json.loads(raw)
            if isinstance(problem, dict):
                candidate_code = problem.get("code")
                candidate_detail = problem.get("detail")
                candidate_request_id = problem.get("requestId")
                if isinstance(candidate_code, str) and candidate_code:
                    code = candidate_code
                if isinstance(candidate_detail, str) and candidate_detail:
                    detail = candidate_detail
                if isinstance(candidate_request_id, str) and candidate_request_id:
                    request_id = candidate_request_id
    except (UnicodeDecodeError, json.JSONDecodeError, OSError, http.client.HTTPException):
        pass
    finally:
        try:
            error.close()
        except (OSError, http.client.HTTPException):
            pass
    return ClientError(
        code,
        detail,
        status=error.code,
        request_id=request_id,
        retry_after_seconds=retry_after_seconds,
    )


def _session_tokens(session: Mapping[str, Any]) -> Tuple[str, str]:
    access_token = session.get("accessToken")
    refresh_token = session.get("refreshToken")
    if not isinstance(access_token, str) or not isinstance(refresh_token, str):
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid session.",
        )
    return (
        _require_secret(access_token, "access token"),
        _require_secret(refresh_token, "refresh token"),
    )


def _require_access_token(value: Optional[str]) -> str:
    if value:
        return value
    raise ClientError(
        "reauthentication_required",
        "No Broker session is available; run login.",
    )


def _require_secret(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ClientError("invalid_response", f"Broker returned an empty {label}.")
    return stripped


def _optional_secret(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _normalized_origin(
    parsed: urllib.parse.SplitResult,
) -> Tuple[str, str, Optional[int]]:
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, (parsed.hostname or "").lower(), port


def _validate_verification_url(value: str, broker_url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        broker = urllib.parse.urlsplit(broker_url)
        origins_match = _normalized_origin(parsed) == _normalized_origin(broker)
    except ValueError:
        raise ClientError(
            "invalid_response",
            "Broker returned an unsafe verification URL.",
        ) from None
    if (
        not origins_match
        or parsed.path != "/auth/dingtalk/start"
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ClientError(
            "invalid_response",
            "Broker returned an unsafe verification URL.",
        )
    try:
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    except ValueError:
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid verification URL.",
        ) from None
    if set(query) != {"user_code"} or len(query["user_code"]) != 1:
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid verification URL.",
        )
    return value


def _content_length(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        length = int(value)
    except ValueError:
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid Content-Length.",
        ) from None
    if length < 0:
        raise ClientError(
            "invalid_response",
            "Broker returned an invalid Content-Length.",
        )
    return length


def _validate_identifier(value: str, label: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > 512
        or any(
            char.isspace() or ord(char) < 32 or char in "/\\"
            for char in normalized
        )
    ):
        raise ClientError(
            "invalid_identifier",
            f"{label} must be a single printable identifier of at most 512 bytes.",
        )
    return normalized


def _validate_process_instance_id(value: str) -> str:
    normalized = _validate_identifier(value, "processInstanceId")
    if normalized.upper().startswith("PROC-"):
        raise ClientError(
            "invalid_process_instance_id",
            "processInstanceId must not be a DingTalk approval template processCode.",
        )
    return normalized


def _validate_category(value: str) -> str:
    normalized = value.strip()
    if re.fullmatch(r"[a-z][a-z0-9-]{0,62}", normalized) is None:
        raise ClientError(
            "invalid_category",
            "Approval category must be a lowercase kebab-case identifier.",
        )
    return normalized


def _validate_keyword(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_KEYWORD_CHARACTERS:
        raise ClientError(
            "invalid_keyword",
            (
                "Keyword must contain between 1 and "
                f"{MAX_KEYWORD_CHARACTERS} Unicode characters."
            ),
        )
    return normalized


def _validate_rfc3339(value: str, label: str) -> str:
    normalized, _ = _parse_rfc3339(value, label)
    return normalized


def _validate_time_window(
    created_after: Optional[str],
    created_before: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    created_after_value: Optional[str] = None
    created_after_time: Optional[datetime.datetime] = None
    created_before_value: Optional[str] = None
    created_before_time: Optional[datetime.datetime] = None
    if created_after is not None:
        created_after_value, created_after_time = _parse_rfc3339(
            created_after,
            "createdAfter",
        )
    if created_before is not None:
        created_before_value, created_before_time = _parse_rfc3339(
            created_before,
            "createdBefore",
        )
    if created_after_time is not None and created_before_time is not None:
        if created_before_time <= created_after_time:
            raise ClientError(
                "invalid_search_parameters",
                "createdBefore must be later than createdAfter.",
            )
        if created_before_time - created_after_time > datetime.timedelta(days=120):
            raise ClientError(
                "invalid_search_parameters",
                "Approval search time range must not exceed 120 days.",
            )
    return created_after_value, created_before_value


def _parse_rfc3339(
    value: str,
    label: str,
) -> Tuple[str, datetime.datetime]:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 64
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
            normalized,
        )
        is None
    ):
        raise ClientError(
            "invalid_time",
            f"{label} must be an RFC3339 timestamp.",
        )
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.datetime.fromisoformat(candidate)
    except ValueError:
        raise ClientError(
            "invalid_time",
            f"{label} must be an RFC3339 timestamp.",
        ) from None
    if parsed.tzinfo is None:
        raise ClientError(
            "invalid_time",
            f"{label} must include a timezone.",
        )
    return normalized, parsed


def _validate_cursor(value: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 16_384
        or any(ord(character) < 33 or ord(character) > 126 for character in normalized)
    ):
        raise ClientError(
            "invalid_cursor",
            "Approval search cursor is invalid.",
        )
    return normalized

def _validate_request_timeout(value: float) -> float:
    if isinstance(value, bool) or not 1 <= value <= 600:
        raise ClientError(
            "invalid_request_timeout",
            "Request timeout must be between 1 and 600 seconds.",
        )
    return float(value)

def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ClientError("invalid_response", f"{label} must be a positive integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ClientError(
            "invalid_response",
            f"{label} must be a positive integer.",
        ) from None
    if parsed <= 0:
        raise ClientError("invalid_response", f"{label} must be a positive integer.")
    return parsed


def emit_json(payload: Mapping[str, Any], *, stream: Any = None) -> None:
    if stream is None:
        stream = sys.stdout
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        file=stream,
        flush=True,
    )


def configure_standard_streams() -> None:
    """Keep machine-readable JSON independent of the Windows console code page."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict")


def build_parser() -> argparse.ArgumentParser:
    parser = StructuredArgumentParser(
        description="Secure DingTalk OA Attachment Broker client.",
    )
    parser.add_argument(
        "--broker-url",
        default=os.environ.get(BROKER_URL_ENV),
        help=f"Broker origin; defaults to {BROKER_URL_ENV}.",
    )
    parser.add_argument(
        "--credential-file",
        type=Path,
        default=os.environ.get(CREDENTIAL_FILE_ENV) or None,
        help=(
            "Absolute local JSON credential path; defaults to "
            f"{CREDENTIAL_FILE_ENV} or the Skill-local runtime file."
        ),
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Broker request timeout in seconds between 1 and 600 (default: 300).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser(
        "login",
        help="Authorize this device and store the Broker session securely.",
    )
    login_parser.add_argument(
        "--no-open",
        action="store_true",
        help="Print the verification URL without opening a browser.",
    )
    login_parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Maximum polling duration in seconds (default: 600).",
    )

    subparsers.add_parser(
        "auth-status",
        help="Validate the cached Broker session and show the current identity.",
    )

    subparsers.add_parser(
        "logout",
        help="Revoke the current Broker session and remove its local cache.",
    )

    list_parser = subparsers.add_parser(
        "list",
        help="List authorized attachments for a process instance.",
    )
    list_parser.add_argument("--process-instance-id", required=True)

    subparsers.add_parser(
        "categories",
        help="List the first page of the current user's visible templates.",
    )

    my_categories_parser = subparsers.add_parser(
        "my-categories",
        help="List DingTalk approval templates visible to the current user.",
    )
    my_categories_parser.add_argument("--q")
    my_categories_parser.add_argument("--cursor")
    page_group = my_categories_parser.add_mutually_exclusive_group()
    page_group.add_argument(
        "--max-pages",
        type=int,
        default=1,
        help="Maximum Broker pages to fetch between 1 and 100 (default: 1).",
    )
    page_group.add_argument(
        "--all",
        action="store_true",
        help="Follow category cursors until complete or the 100-page safety cap.",
    )

    search_parser = subparsers.add_parser(
        "search",
        help="Search authorized approvals with attachments by category.",
    )
    search_parser.add_argument("--category", required=True)
    search_parser.add_argument("--q")
    search_parser.add_argument("--created-after")
    search_parser.add_argument("--created-before")
    search_parser.add_argument("--cursor")
    search_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Candidate page size between 10 and 20 (default: 20).",
    )

    download_parser = subparsers.add_parser(
        "download",
        help="Download one authorized attachment atomically.",
    )
    download_parser.add_argument("--process-instance-id", required=True)
    download_parser.add_argument("--file-id", required=True)
    download_parser.add_argument("--output", required=True, type=Path)
    download_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace an existing output file.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    configure_standard_streams()
    try:
        arguments = build_parser().parse_args(argv)
        if arguments.command == "login" and not (1 <= arguments.timeout <= 600):
            raise ClientError(
                "invalid_timeout",
                "Login timeout must be between 1 and 600 seconds.",
            )
        request_timeout = _validate_request_timeout(arguments.request_timeout)
        broker_url = validate_broker_url(arguments.broker_url)
        if arguments.credential_file is None:
            store = select_credential_store(broker_url)
        else:
            store = select_credential_store(
                broker_url,
                arguments.credential_file,
            )
        client = BrokerClient(
            broker_url,
            store,
            timeout=request_timeout,
        )

        if arguments.command == "login":
            command_login(
                client,
                open_browser=not arguments.no_open,
                timeout_seconds=arguments.timeout,
            )
        elif arguments.command == "auth-status":
            command_auth_status(client)
        elif arguments.command == "logout":
            command_logout(client)
        elif arguments.command == "list":
            command_list(client, arguments.process_instance_id)
        elif arguments.command == "categories":
            command_categories(client)
        elif arguments.command == "my-categories":
            command_my_categories(
                client,
                keyword=arguments.q,
                cursor=arguments.cursor,
                max_pages=arguments.max_pages,
                all_pages=arguments.all,
            )
        elif arguments.command == "search":
            command_search(
                client,
                arguments.category,
                keyword=arguments.q,
                created_after=arguments.created_after,
                created_before=arguments.created_before,
                cursor=arguments.cursor,
                limit=arguments.limit,
            )
        elif arguments.command == "download":
            command_download(
                client,
                arguments.process_instance_id,
                arguments.file_id,
                arguments.output,
                overwrite=arguments.overwrite,
            )
        else:
            raise ClientError("invalid_command", "Unsupported command.")
        return 0
    except ClientError as error:
        payload: Dict[str, Any] = {
            "ok": False,
            "code": error.code,
            "detail": error.detail,
        }
        if error.status is not None:
            payload["status"] = error.status
        if error.request_id:
            payload["requestId"] = error.request_id
        if error.retry_after_seconds is not None:
            payload["retryAfterSeconds"] = error.retry_after_seconds
        emit_json(payload, stream=sys.stderr)
        return 1
    except KeyboardInterrupt:
        emit_json(
            {
                "ok": False,
                "code": "interrupted",
                "detail": "Operation interrupted.",
            },
            stream=sys.stderr,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
