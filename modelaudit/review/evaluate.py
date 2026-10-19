"""Opt-in replay of pre-PR scanner findings; labels never enter the reviewer request."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .bundle import digest, write_json
from .codex import DockerReviewer
from .models import Artifact
from .render import render_markdown
from .runner import Reviewer, review_findings


def replay(case: dict[str, Any], output: Path, reviewer: Reviewer | None) -> dict[str, Any]:
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    artifacts = output / "artifacts"
    artifacts.mkdir(mode=0o755)
    content = case["document"].encode("utf-8")
    if digest(content) != case["document_sha256"]:
        raise ValueError("Evaluation document digest mismatch")
    (artifacts / "README.md").write_bytes(content)
    (artifacts / "README.md").chmod(0o444)

    def relocate(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace("/artifacts/README.md", str(artifacts / "README.md"))
        if isinstance(value, dict):
            return {key: relocate(item) for key, item in value.items()}
        if isinstance(value, list):
            return [relocate(item) for item in value]
        return value

    # Only location relocation is applied to the recorded scanner report before freezing it.
    report = relocate(case["report"])
    raw = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode()
    (output / "scan.json").write_bytes(raw)
    (output / "scan.json").chmod(0o400)
    artifact = Artifact(path="README.md", sha256=digest(content), size=len(content), role="documentation")
    review = review_findings(report, raw, case["scan_exit_code"], [artifact], artifacts, output, reviewer)
    write_json(output / "review.json", review.model_dump())
    (output / "review.md").write_text(render_markdown(review))
    if (output / "scan.json").read_bytes() != raw:
        raise ValueError("Evaluation changed the frozen scanner report")
    return {
        "case_id": case["case_id"],
        "expected_display": case["expected_display"],
        "requires_execution_warning": case["requires_execution_warning"],
        "scan_exit_code": review.scan_exit_code,
        "scan_sha256": review.scan_sha256,
        "review_status": review.review_status,
        "selected": review.selected_count,
        "reviewed": review.reviewed_count,
        "de_emphasized": sum(entry.display_action == "de_emphasize" for entry in review.entries),
        "execution_implications": [
            entry.assessment.execution_implications for entry in review.entries if entry.assessment
        ],
    }


def score(results: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in results if r["expected_display"] == "de_emphasize" and r["selected"] > 0]
    return {
        "cases": len(results),
        "alert_cases": sum(r["selected"] > 0 for r in results),
        "unsafe_de_emphasis": sum(r["de_emphasized"] > 0 for r in results if r["expected_display"] == "retain"),
        "benign_cases": len(benign),
        "benign_resolved": sum(
            r["review_status"] == "complete" and r["de_emphasized"] == r["selected"] for r in benign
        ),
        "incomplete_reviews": sum(r["review_status"] not in {"complete", "not_needed"} for r in results),
        "note": "Manually review execution implications; this scorer does not judge their semantic accuracy.",
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--worker-network", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--codex-model", required=True)
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("Use between 1 and 10 repeats")
    fixture = json.loads(args.cases.read_bytes())
    output = args.output_dir.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    reviewer = DockerReviewer(args.worker_image, args.worker_network, args.proxy_url, args.codex_model)
    results = []
    for repeat in range(args.runs):
        for index, case in enumerate(fixture["cases"]):
            # Ordinal paths avoid exposing descriptive case names or expected labels to the agent.
            results.append(replay(case, output / f"{repeat:02d}-{index:03d}", reviewer))
    summary = score(results)
    summary.update(
        provenance=fixture["provenance"],
        model=args.codex_model,
        worker_image=args.worker_image,
        fixture_sha256=digest(args.cases.read_bytes()),
    )
    write_json(output / "evaluation.json", summary)
    print(json.dumps({key: value for key, value in summary.items() if key not in {"results", "provenance"}}, indent=2))
    raise SystemExit(1 if summary["unsafe_de_emphasis"] or summary["incomplete_reviews"] else 0)


if __name__ == "__main__":
    main()
