"""Codex adapter. The only executable backend is an isolated Docker worker."""

from __future__ import annotations

import json
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .bundle import write_json
from .models import AgentResponse, Evidence, Finding
from .policy import POLICY
from .process import ProcessLimitError, defer_termination, run_bounded

CODEX_VERSION = "0.163.0"


def codex_config(proxy_url: str) -> list[str]:
    settings = [
        'approval_policy="never"',
        'sandbox_mode="workspace-write"',
        "sandbox_workspace_write.network_access=false",
        'web_search="disabled"',
        "project_doc_max_bytes=0",
        "project_root_markers=[]",
        'shell_environment_policy.inherit="none"',
        'shell_environment_policy.set={PATH="/usr/local/bin:/usr/bin:/bin",PROMPTFOO_DISABLE_TELEMETRY="1"}',
        "features.apps=false",
        "features.memories=false",
        "features.goals=false",
        "features.view_image=false",
        "features.api_key_model_discovery=false",
        "features.multi_agent=false",
        "features.hooks=false",
        "features.plugins=false",
        "features.remote_plugin=false",
        "features.skip_host_skill_discovery=true",
        "features.skill_search=false",
        "features.skill_mcp_dependency_install=false",
        "features.browser_use=false",
        "features.browser_use_external=false",
        "features.computer_use=false",
        "features.image_generation=false",
        "features.standalone_web_search=false",
        "features.workspace_dependencies=false",
        "features.shell_snapshot=false",
        "features.daemon_auto_start=false",
        "features.enable_request_compression=false",
        "features.unbounded_connection_retries=false",
        'model_provider="review"',
        'model_providers.review.name="Review gateway"',
        f"model_providers.review.base_url={json.dumps(proxy_url)}",
        'model_providers.review.wire_api="responses"',
        "model_providers.review.requires_openai_auth=false",
        "model_providers.review.request_max_retries=0",
        "model_providers.review.stream_max_retries=0",
    ]
    return [arg for setting in settings for arg in ("-c", setting)]


def codex_command(model: str, proxy_url: str) -> list[str]:
    return [
        "codex",
        "exec",
        "--model",
        model,
        "--sandbox",
        "workspace-write",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--ephemeral",
        "--skip-git-repo-check",
        "--json",
        "--color",
        "never",
        "--output-schema",
        "/request/schema.json",
        "--cd",
        "/work",
        *codex_config(proxy_url),
        "-",
    ]


def extract_response(events: bytes) -> AgentResponse:
    final: str | None = None
    completed = False
    for line in events.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("Invalid Codex event")
        if event.get("type") in {"error", "turn.failed"}:
            raise ValueError("Codex reported a failed turn")
        if event.get("type") == "turn.completed":
            completed = True
        item = event.get("item", {})
        if event.get("type") == "item.completed" and isinstance(item, dict) and item.get("type") == "agent_message":
            final = item.get("text")
    if not completed or not isinstance(final, str):
        raise ValueError("Codex did not produce a completed structured response")
    return AgentResponse.model_validate_json(final)


@dataclass(frozen=True)
class DockerReviewer:
    image: str
    network: str
    proxy_url: str
    model: str
    timeout: float = 300

    def validate(self, cwd: Path) -> None:
        if not re.fullmatch(r"(?:[A-Za-z0-9][A-Za-z0-9./:_-]*@)?sha256:[0-9a-f]{64}", self.image):
            raise ValueError("Worker image must be pinned by sha256 digest")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.network):
            raise ValueError("Invalid isolated worker network name")
        url = urlsplit(self.proxy_url)
        if (
            url.scheme != "http"
            or not url.hostname
            or url.username
            or url.password
            or url.path != "/v1"
            or url.query
            or url.fragment
        ):
            raise ValueError("Use a credential-free HTTP gateway URL ending in /v1 on the internal Docker network")
        result = run_bounded(["docker", "network", "inspect", self.network], cwd=cwd, timeout=15)
        if result.returncode:
            raise ValueError("Cannot inspect the isolated worker network")
        networks = json.loads(result.stdout)
        if len(networks) != 1 or networks[0].get("Internal") is not True or networks[0].get("Driver") != "bridge":
            raise ValueError("Reviewer requires an internal bridge network with an operator-provisioned gateway")

    def review(self, findings: list[Finding], evidence: list[Evidence], artifacts: Path, output: Path) -> AgentResponse:
        write_json(
            output / "backend.json",
            {
                "model": self.model,
                "image": self.image,
                "network": self.network,
                "proxy_url": self.proxy_url,
                "codex_version": CODEX_VERSION,
            },
        )
        self.validate(output)
        request = output / "request"
        request.mkdir(mode=0o755)
        request.chmod(0o755)
        write_json(request / "schema.json", AgentResponse.model_json_schema())
        write_json(
            request / "evidence.json",
            {
                "findings": [f.model_dump() for f in findings],
                "evidence": [e.model_dump() for e in evidence],
            },
        )
        for path in request.iterdir():
            path.chmod(0o444)
        for path in (request, artifacts):
            if any(character in str(path) for character in (",", "\n", "\r")):
                raise ValueError("Docker bind paths cannot contain commas or newlines")
        name = f"modelaudit-review-{uuid.uuid4().hex}"
        # Docker client proxy configuration can inject credentials and redirect gateway requests.
        proxy_environment = [
            argument
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY")
            for key in (name, name.lower())
            for argument in ("--env", f"{key}=")
        ]
        command = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--name",
            name,
            "--interactive",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--cpus=2",
            "--memory=4g",
            "--memory-swap=4g",
            "--pids-limit=128",
            "--network",
            self.network,
            *proxy_environment,
            "--tmpfs",
            "/work:rw,nosuid,nodev,size=268435456,uid=10001,gid=10001,mode=700",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=134217728,mode=1777",
            "--tmpfs",
            "/home/reviewer:rw,nosuid,nodev,size=134217728,uid=10001,gid=10001,mode=700",
            "--mount",
            f"type=bind,src={request},dst=/request,readonly",
            "--mount",
            f"type=bind,src={artifacts},dst=/artifacts,readonly",
            "--workdir",
            "/work",
            "--entrypoint",
            "python",
            self.image,
            "-m",
            "modelaudit.review.worker",
            "--model",
            self.model,
            "--proxy-url",
            self.proxy_url,
        ]
        write_json(
            output / "invocation.json",
            {
                "argv": command,
                "codex_version": CODEX_VERSION,
                "timeout_seconds": self.timeout,
                "max_output_bytes": 4 * 1024 * 1024,
            },
        )
        try:
            try:
                result = run_bounded(
                    command,
                    cwd=output,
                    timeout=self.timeout,
                    stdin=(POLICY + "\nRead /request/evidence.json.\n").encode(),
                )
            except ProcessLimitError as exc:
                (output / "trace.jsonl").write_bytes(exc.stdout)
                (output / "stderr.txt").write_bytes(exc.stderr)
                raise
            (output / "trace.jsonl").write_bytes(result.stdout)
            (output / "stderr.txt").write_bytes(result.stderr)
            if result.returncode:
                raise ValueError(f"Isolated Codex worker exited with code {result.returncode}; see stderr.txt")
            return extract_response(result.stdout)
        finally:
            # Killing the docker client alone does not stop a daemon-owned container.
            interrupted = isinstance(sys.exc_info()[1], (KeyboardInterrupt, SystemExit))
            with defer_termination():
                try:
                    cleanup = run_bounded(["docker", "rm", "--force", name], cwd=output, timeout=15)
                    if cleanup.returncode and b"No such container" not in cleanup.stderr:
                        raise ValueError("Docker could not remove the worker")
                except Exception as exc:
                    message = f"Worker cleanup failed; remove {name} (see invocation.json)"
                    print(message, file=sys.stderr)
                    if not interrupted:
                        raise ValueError(message) from exc
