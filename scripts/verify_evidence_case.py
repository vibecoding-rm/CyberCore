"""Verify an exported CyberCore evidence case bundle offline.

    python -m scripts.verify_evidence_case evidence-case.json --public-key cybercore.pub.pem

The public key must come from a trusted channel (not from the bundle's sender
alongside the bundle); compare its signing_key_id with the server's
GET /v1/evidence/signing-key.
"""

import argparse
import json
from pathlib import Path

from app.api.models import EvidenceCaseBundle
from app.core.evidence_bundle import evidence_case_integrity_issues
from app.core.evidence_signing import load_public_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()

    try:
        bundle = EvidenceCaseBundle.model_validate_json(
            args.bundle.read_text(encoding="utf-8")
        )
        public_key = load_public_key(args.public_key.read_bytes())
    except (OSError, ValueError) as exc:
        print(json.dumps({"valid": False, "issues": [str(exc)]}, ensure_ascii=False, indent=2))
        return 2
    issues = evidence_case_integrity_issues(bundle, public_key)
    print(json.dumps({
        "valid": not issues,
        "case_id": bundle.case_id,
        "signing_key_id": bundle.signing_key_id,
        "bundle_sha256": bundle.bundle_sha256,
        "issues": issues,
    }, ensure_ascii=False, indent=2))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
