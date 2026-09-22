import argparse
import json
import secrets

from app.core.auth import ApiKeyAuthenticator, ApiCredential


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Genera una credencial local de alta entropía para CyberCore."
    )
    parser.add_argument("subject", help="Identidad estable, por ejemplo maikel")
    parser.add_argument(
        "--role",
        choices=("viewer", "operator"),
        default="operator",
    )
    args = parser.parse_args()

    api_key = secrets.token_urlsafe(32)
    credential = ApiCredential(
        subject=args.subject,
        role=args.role,
        key_sha256=ApiKeyAuthenticator.hash_api_key(api_key),
    )
    encoded = json.dumps(
        [credential.model_dump()],
        ensure_ascii=False,
        separators=(",", ":"),
    )

    print("Guarda esta clave ahora; CyberCore no puede recuperarla después:")
    print(api_key)
    print("\nAñade esta línea a .env:")
    print(f"API_CREDENTIALS_JSON='{encoded}'")


if __name__ == "__main__":
    main()
