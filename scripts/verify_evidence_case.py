"""Verify an exported CyberCore Evidence Case Bundle offline.

    python -m scripts.verify_evidence_case evidence-case.json
"""

import argparse
import json
from pathlib import Path

from app.api.models import EvidenceCaseBundle
from app.core.evidence_bundle import evidence_case_integrity_issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()

    try:
        bundle = EvidenceCaseBundle.model_validate_json(
            args.bundle.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"valid": False, "issues": [str(exc)]}, ensure_ascii=False, indent=2))
        return 2
    issues = evidence_case_integrity_issues(bundle)
    print(json.dumps({
        "valid": not issues,
        "case_id": bundle.case_id,
        "bundle_sha256": bundle.bundle_sha256,
        "issues": issues,
    }, ensure_ascii=False, indent=2))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
