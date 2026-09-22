import hashlib
import json
from dataclasses import dataclass
from secrets import compare_digest
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


Role = Literal["viewer", "operator"]


class ApiCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    role: Role
    key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Principal:
    subject: str
    role: Role


class ApiKeyAuthenticator:
    def __init__(self, credentials: list[ApiCredential]):
        if len(credentials) > 100:
            raise ValueError("No se permiten más de 100 credenciales de API")

        hashes = [credential.key_sha256 for credential in credentials]
        if len(hashes) != len(set(hashes)):
            raise ValueError("Las credenciales de API contienen hashes duplicados")

        self.credentials = tuple(credentials)

    @classmethod
    def from_json(cls, raw_credentials: str) -> "ApiKeyAuthenticator":
        try:
            loaded = json.loads(raw_credentials)
        except json.JSONDecodeError as exc:
            raise ValueError("API_CREDENTIALS_JSON no contiene JSON válido") from exc

        if not isinstance(loaded, list):
            raise ValueError("API_CREDENTIALS_JSON debe ser una lista")

        try:
            credentials = [ApiCredential.model_validate(item) for item in loaded]
        except ValidationError as exc:
            raise ValueError("API_CREDENTIALS_JSON contiene credenciales inválidas") from exc
        return cls(credentials)

    @property
    def configured(self) -> bool:
        return bool(self.credentials)

    def authenticate(self, api_key: str) -> Principal | None:
        if not 32 <= len(api_key) <= 512:
            return None

        candidate_hash = self.hash_api_key(api_key)
        matched: Principal | None = None
        for credential in self.credentials:
            if compare_digest(candidate_hash, credential.key_sha256):
                matched = Principal(
                    subject=credential.subject,
                    role=credential.role,
                )
        return matched

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
