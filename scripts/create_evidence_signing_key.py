"""Create the Ed25519 key that signs evidence case bundles.

    python -m scripts.create_evidence_signing_key
    python -m scripts.create_evidence_signing_key --output secrets/other.pem

Writes the private key (never commit it; secrets/ is ignored by git) and the
public key next to it with a .pub.pem suffix, which is what verifiers need.
Refuses to overwrite an existing key: bundles signed with it would no longer
verify against a new one.
"""

import argparse
import os
from pathlib import Path

from app.core.evidence_signing import EvidenceSigner, public_key_pem


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=Path("secrets/evidence_signing_ed25519.pem"))
    args = parser.parse_args()

    public = args.output.with_suffix(".pub.pem")
    if args.output.exists():
        print(f"{args.output} ya existe; no se sobrescribe")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    signer = EvidenceSigner.generate()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(signer.private_pem())
    public.write_text(public_key_pem(signer.public_key), encoding="ascii")
    print(f"Clave privada: {args.output}\nClave pública: {public}\nsigning_key_id: {signer.key_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
