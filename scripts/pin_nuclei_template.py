import argparse
import hashlib
from pathlib import Path

import yaml

from app.settings import get_settings
from app.tools.nuclei_catalog import AllowedTemplate, inspect_template_content


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        description="Revisa una plantilla Nuclei y la añade fijada por SHA-256 al allowlist.",
    )
    parser.add_argument("path", help="Ruta relativa dentro de NUCLEI_TEMPLATES_DIR")
    parser.add_argument("--mode", choices=["passive", "active"], required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--allowlist", default=str(settings.nuclei_allowlist_file))
    args = parser.parse_args()

    templates_dir = Path(settings.nuclei_templates_dir).expanduser().resolve()
    file_path = (templates_dir / args.path).resolve()
    if not file_path.is_relative_to(templates_dir):
        raise SystemExit("La ruta sale de NUCLEI_TEMPLATES_DIR")
    content = file_path.read_bytes()
    template_id = (yaml.safe_load(content) or {}).get("id", "")
    inspect_template_content(content, template_id)

    entry = AllowedTemplate(
        id=template_id,
        path=args.path,
        sha256=hashlib.sha256(content).hexdigest(),
        mode=args.mode,
        description=args.description,
    )
    allowlist = Path(args.allowlist)
    data = yaml.safe_load(allowlist.read_text(encoding="utf-8")) or {}
    templates = [t for t in data.get("templates") or [] if t.get("id") != entry.id]
    templates.append(entry.model_dump())
    header = "".join(
        line for line in allowlist.read_text(encoding="utf-8").splitlines(keepends=True)
        if line.startswith("#")
    )
    allowlist.write_text(
        header + yaml.safe_dump({"templates": templates}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"Fijada {entry.id} ({entry.mode}) sha256={entry.sha256}")


if __name__ == "__main__":
    main()
