"""Opt-in entry point; the existing modelaudit CLI does not import this package."""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from types import FrameType

from .codex import DockerReviewer
from .runner import run


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Experimental advisory README/model-card review; preserves scanner exit codes"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True, help="New private bundle directory outside input")
    parser.add_argument("--prepare-only", action="store_true", help="Scan and build evidence without calling Codex")
    parser.add_argument("--worker-image", help="Trusted worker image pinned by sha256 digest")
    parser.add_argument("--worker-network", help="Internal Docker bridge with a credential gateway")
    parser.add_argument("--proxy-url", help="Credential-free gateway URL on that network, ending in /v1")
    parser.add_argument("--codex-model", help="Explicit model routed by the gateway")
    parser.add_argument("--review-timeout", type=int, default=300)
    parser.add_argument(
        "--max-review-groups", type=int, default=8, help="Maximum documents sent to fresh Codex workers"
    )
    parser.add_argument("--scan-timeout", type=int, default=300)
    parser.add_argument("--max-snapshot-bytes", type=int, default=2 * 1024**3)
    args = parser.parse_args()
    if min(args.review_timeout, args.scan_timeout, args.max_snapshot_bytes, args.max_review_groups) <= 0:
        parser.error("Resource limits must be positive")
    reviewer = None
    if not args.prepare_only:
        if not all((args.worker_image, args.worker_network, args.proxy_url, args.codex_model)):
            parser.error("Review requires --worker-image, --worker-network, --proxy-url and --codex-model")
        reviewer = DockerReviewer(
            args.worker_image, args.worker_network, args.proxy_url, args.codex_model, args.review_timeout
        )
    try:
        return run(
            args.input,
            args.output_dir,
            reviewer,
            max_snapshot_bytes=args.max_snapshot_bytes,
            scan_timeout=args.scan_timeout,
            max_review_groups=args.max_review_groups,
        )
    except KeyboardInterrupt:
        print("Review interrupted by user", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"Review could not start: {str(exc)!a}", file=sys.stderr)
        return 2


def terminate(signum: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    raise SystemExit(main())
