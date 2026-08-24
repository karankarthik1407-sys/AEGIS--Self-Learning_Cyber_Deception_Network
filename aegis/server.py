from __future__ import annotations

import argparse
import hashlib
import html
import json
import mimetypes
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .access import OperatorSession
from .config import SETTINGS
from .service import AegisService
from .sensor_gateway import GatewayValidationError
from .registry import RegistryValidationError
from .version import PRODUCT_VERSION, SERVER_VERSION


class AegisHandler(BaseHTTPRequestHandler):
    service: AegisService
    static_root: Path
    session_token: str | None = None
    operator_session: OperatorSession
    server_version = SERVER_VERSION

    def log_message(self, format: str, *args: object) -> None:
        print(f"[AEGIS] {self.address_string()} - {format % args}")

    def desktop_host_is_valid(self) -> bool:
        if self.session_token is None:
            return True
        hostname = urlparse(f"//{self.headers.get('Host', '')}").hostname
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def do_GET(self) -> None:
        if not self.desktop_host_is_valid():
            return self.send_json({"error": "loopback_host_required"}, HTTPStatus.MISDIRECTED_REQUEST)
        request = urlparse(self.path)
        path = request.path
        if path == "/api/health":
            return self.send_json({"status": "healthy", "product": "AEGIS", "release": PRODUCT_VERSION, "mode": "resident-local-active-authorized-range", "license_state": self.service.license_manager.status()["state"]})
        if path == "/api/access/status":
            return self.send_json(self.service.access_status(self.operator_session))
        if path == "/api/license/status":
            return self.send_json(self.service.license_manager.status())
        if path == "/api/audit/verify":
            return self.send_json(self.service.verify_audit())
        if path == "/api/audit/events":
            raw_limit = parse_qs(request.query).get("limit", ["100"])[0]
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                return self.send_json({"error": "invalid_limit"}, HTTPStatus.BAD_REQUEST)
            return self.send_json(self.service.audit_events(limit))
        if path == "/api/overview":
            return self.send_json(self.service.overview())
        if path == "/api/cases":
            return self.send_json({"cases": self.service.list_cases()})
        if path.startswith("/api/cases/") and path.endswith("/bundle"):
            case_id = unquote(path.removeprefix("/api/cases/").removesuffix("/bundle").rstrip("/"))
            bundle = self.service.case_bundle(case_id)
            return self.send_json(bundle or {"error": "case_not_found"}, HTTPStatus.OK if bundle else HTTPStatus.NOT_FOUND)
        if path.startswith("/api/cases/"):
            case_id = unquote(path.removeprefix("/api/cases/"))
            case = self.service.case_detail(case_id)
            return self.send_json(case or {"error": "case_not_found"}, HTTPStatus.OK if case else HTTPStatus.NOT_FOUND)
        if path == "/api/topology":
            return self.send_json(self.service.topology())
        if path == "/api/evidence/verify":
            return self.send_json(self.service.verify_evidence())
        if path == "/api/certificates/latest":
            return self.send_json(self.service.latest_certificate() or {"certificate": None})
        if path == "/api/investigation/campaigns":
            return self.send_json(self.service.campaigns())
        if path == "/api/investigation/indicators":
            return self.send_json(self.service.indicators())
        if path == "/api/trace/report":
            return self.send_json(self.service.threat_trace())
        if path == "/api/trace/experiment":
            return self.send_json(self.service.trace_experiment())
        if path == "/api/trace/graph-experiment":
            return self.send_json(self.service.trace_graph_experiment())
        if path == "/api/steering/experiment":
            return self.send_json(self.service.steering_experiment())
        if path == "/api/deception/assets":
            return self.send_json(self.service.deception_assets())
        if path == "/api/research/status":
            return self.send_json(self.service.research_status())
        if path == "/api/research/experiment":
            return self.send_json(self.service.research_experiment())
        if path == "/api/research/dataset":
            return self.send_json(self.service.research_dataset())
        if path == "/api/models/fabric":
            return self.send_json(self.service.learning_status())
        if path == "/api/system/agents":
            return self.send_json(self.service.system_agents())
        if path == "/api/telemetry/status":
            return self.send_json(self.service.telemetry_status())
        if path == "/api/gateway/status":
            return self.send_json(self.service.gateway_status())
        if path == "/api/governance/status":
            return self.send_json(self.service.governance_status())
        if path == "/api/governance/verify":
            return self.send_json(self.service.verify_governance())
        if path == "/api/gateway/sample":
            connector = parse_qs(request.query).get("connector", ["suricata-eve-json"])[0]
            try:
                return self.send_json(self.service.gateway_sample(connector))
            except GatewayValidationError as error:
                return self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/telemetry/events":
            raw_limit = parse_qs(request.query).get("limit", ["100"])[0]
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                return self.send_json({"error": "invalid_limit"}, HTTPStatus.BAD_REQUEST)
            return self.send_json(self.service.telemetry_events(limit))
        if path == "/api/hardware/profile":
            return self.send_json(self.service.hardware_profile())
        if path.startswith("/api/"):
            return self.send_json({"error": "route_not_found"}, HTTPStatus.NOT_FOUND)
        return self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        self._audit_completion = None
        contract = self.service.access_controller.contract_for(path)
        context = {
            "command_id": "CMD-" + secrets.token_hex(12).upper(),
            "path": path,
            "permission": contract.permission,
            "entitlement": contract.entitlement,
            "request_sha256": hashlib.sha256(b"").hexdigest(),
        }
        if not self.service.audit_operational():
            return self.send_json(
                {"error": "audit_journal_unavailable", "detail": "Mutations fail closed until local audit integrity is restored."},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        if not self.desktop_host_is_valid():
            return self.deny_post(
                context,
                "DENIED_HOST",
                "loopback_host_required",
                HTTPStatus.MISDIRECTED_REQUEST,
                authenticated=False,
            )
        if self.session_token is not None:
            supplied = self.headers.get("X-AEGIS-Desktop-Token", "")
            if not supplied or not secrets.compare_digest(supplied, self.session_token):
                return self.deny_post(
                    context,
                    "DENIED_SESSION",
                    "desktop_session_required",
                    HTTPStatus.FORBIDDEN,
                    authenticated=False,
                )
        access = self.service.access_controller.authorize(self.operator_session, path)
        if not access.allowed:
            return self.deny_post(
                context,
                "DENIED_ROLE",
                "operator_scope_required",
                HTTPStatus.FORBIDDEN,
                detail=access.reason,
            )
        if not self.service.license_manager.is_entitled(contract.entitlement):
            license_status = self.service.license_manager.status()
            return self.deny_post(
                context,
                "DENIED_LICENSE",
                "license_entitlement_required",
                HTTPStatus.FORBIDDEN,
                detail=f"{contract.entitlement or 'core'} is unavailable while license state is {license_status['state']}",
            )
        payload, request_digest, body_error = self.read_json_body()
        context["request_sha256"] = request_digest
        if body_error is not None:
            error_name, status = body_error
            return self.deny_post(context, "DENIED_INPUT", error_name, status)
        if not self.record_post_event(context, "ACCEPTED", 0):
            return self.send_json(
                {"error": "audit_write_failed", "detail": "The command was not executed."},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        self._audit_completion = context
        if path == "/api/simulate":
            return self.send_json(self.service.simulate(payload), HTTPStatus.CREATED)
        if path == "/api/actions/evaluate":
            return self.send_json(self.service.evaluate_action(payload), HTTPStatus.CREATED)
        if path == "/api/demo/reset":
            return self.send_json(self.service.reset_demo())
        if path == "/api/research/experiment/run":
            return self.send_json(self.service.run_research_experiment(payload), HTTPStatus.CREATED)
        if path == "/api/trace/experiment/run":
            return self.send_json(self.service.run_trace_experiment(payload), HTTPStatus.CREATED)
        if path == "/api/trace/graph-experiment/run":
            return self.send_json(self.service.run_trace_graph_experiment(payload), HTTPStatus.CREATED)
        if path == "/api/steering/experiment/run":
            return self.send_json(self.service.run_steering_experiment(payload), HTTPStatus.CREATED)
        if path == "/api/models/fabric/evaluate":
            return self.send_json(self.service.evaluate_learning_candidate(payload), HTTPStatus.CREATED)
        if path == "/api/hardware/dry-run":
            return self.send_json(self.service.hardware_dry_run(payload), HTTPStatus.CREATED)
        if path == "/api/telemetry/collect":
            return self.send_json(self.service.collect_telemetry(), HTTPStatus.CREATED)
        if path in {"/api/gateway/preview", "/api/gateway/import"}:
            try:
                result = (
                    self.service.preview_gateway_records(payload)
                    if path.endswith("/preview")
                    else self.service.import_gateway_records(payload)
                )
                return self.send_json(result, HTTPStatus.CREATED)
            except GatewayValidationError as error:
                return self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/governance/evaluate":
            try:
                return self.send_json(
                    self.service.evaluate_governance_candidate(payload),
                    HTTPStatus.CREATED,
                )
            except RegistryValidationError as error:
                return self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/license/reload":
            return self.send_json(self.service.reload_license(self.operator_session))
        return self.send_json({"error": "route_not_found"}, HTTPStatus.NOT_FOUND)

    def record_post_event(
        self,
        context: dict[str, object],
        decision: str,
        status_code: int,
        authenticated: bool = True,
    ) -> bool:
        session = self.operator_session if authenticated else None
        try:
            self.service.record_operator_command(
                command_id=str(context["command_id"]),
                session_ref=session.session_ref if session else "SES-UNAUTHENTICATED",
                operator_role=session.role if session else "UNAUTHENTICATED",
                method="POST",
                path=str(context["path"]),
                permission=str(context["permission"]),
                entitlement=(
                    str(context["entitlement"]) if context.get("entitlement") is not None else None
                ),
                decision=decision,
                status_code=int(status_code),
                request_sha256=str(context["request_sha256"]),
            )
            return True
        except Exception as error:
            print(f"[AEGIS] audit append failed: {type(error).__name__}")
            return False

    def deny_post(
        self,
        context: dict[str, object],
        decision: str,
        error_name: str,
        status: HTTPStatus,
        *,
        authenticated: bool = True,
        detail: str | None = None,
    ) -> None:
        if not self.record_post_event(context, decision, int(status), authenticated=authenticated):
            return self.send_json(
                {"error": "audit_write_failed", "detail": "The command was not executed."},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        payload: dict[str, object] = {"error": error_name}
        if detail:
            payload["detail"] = detail
        return self.send_json(payload, status)

    def read_json_body(self) -> tuple[dict | None, str, tuple[str, HTTPStatus] | None]:
        empty_digest = hashlib.sha256(b"").hexdigest()
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return None, empty_digest, ("invalid_content_length", HTTPStatus.BAD_REQUEST)
        if length < 0:
            return None, empty_digest, ("invalid_content_length", HTTPStatus.BAD_REQUEST)
        if length > 1_000_000:
            return None, empty_digest, ("payload_too_large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        if length == 0:
            return {}, empty_digest, None
        raw = self.rfile.read(length)
        request_digest = hashlib.sha256(raw).hexdigest()
        try:
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("JSON object required")
            return value, request_digest, None
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            return None, request_digest, ("invalid_json_object", HTTPStatus.BAD_REQUEST)

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        completion = getattr(self, "_audit_completion", None)
        if completion is not None:
            self._audit_completion = None
            decision = "COMPLETED" if int(status) < 400 else "FAILED"
            if not self.record_post_event(completion, decision, int(status)):
                payload = {
                    "error": "audit_completion_failed",
                    "detail": "The command was accepted, but its completion receipt could not be sealed.",
                }
                status = HTTPStatus.INTERNAL_SERVER_ERROR
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def serve_static(self, request_path: str) -> None:
        relative = "index.html" if request_path in ("", "/") else unquote(request_path.lstrip("/"))
        candidate = (self.static_root / relative).resolve()
        try:
            candidate.relative_to(self.static_root.resolve())
        except ValueError:
            return self.send_error(HTTPStatus.FORBIDDEN)
        if not candidate.is_file():
            candidate = self.static_root / "index.html"
        body = candidate.read_bytes()
        if candidate.name == "index.html" and self.session_token is not None:
            markup = body.decode("utf-8")
            placeholder = '<meta name="aegis-session-token" content="">'
            replacement = f'<meta name="aegis-session-token" content="{html.escape(self.session_token, quote=True)}">'
            body = markup.replace(placeholder, replacement, 1).encode("utf-8")
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") or content_type == "application/javascript" else content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)


def handler_factory(
    service: AegisService,
    static_root: Path,
    session_token: str | None = None,
    operator_role: str = "administrator",
):
    class BoundHandler(AegisHandler):
        pass

    BoundHandler.service = service
    BoundHandler.static_root = static_root
    BoundHandler.session_token = session_token
    BoundHandler.operator_session = OperatorSession.create(
        session_token,
        role=operator_role,
        origin="desktop-loopback" if session_token is not None else "resident-loopback",
    )
    return BoundHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AEGIS local control plane")
    parser.add_argument("--host", default=SETTINGS.host)
    parser.add_argument("--port", type=int, default=SETTINGS.port)
    parser.add_argument("--database", type=Path, default=SETTINGS.database_path)
    parser.add_argument("--telemetry-interval", type=int, default=30)
    parser.add_argument("--operator-role", choices=("viewer", "analyst", "administrator"), default="administrator")
    args = parser.parse_args()

    service = AegisService(args.database, telemetry_interval_seconds=args.telemetry_interval)
    server = ThreadingHTTPServer(
        (args.host, args.port),
        handler_factory(service, SETTINGS.static_path, operator_role=args.operator_role),
    )
    print(f"AEGIS Research Edition v{PRODUCT_VERSION} running at http://{args.host}:{args.port}")
    print("Mode: RESIDENT LOCAL NODE / PASSIVE TELEMETRY / AUTHORIZED RANGE")
    service.start_background_services()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAEGIS stopped")
    finally:
        service.stop_background_services()
        server.server_close()


if __name__ == "__main__":
    main()
