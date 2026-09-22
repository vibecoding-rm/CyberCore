from typing import Annotated

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.auth import ApiKeyAuthenticator, Principal


bearer_scheme = HTTPBearer(auto_error=False)


async def require_operator(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ],
) -> Principal:
    return _require_role(request, credentials, "operator")


async def require_approver(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ],
) -> Principal:
    return _require_role(request, credentials, "approver")


def _require_role(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    required_role: str,
) -> Principal:
    authenticator: ApiKeyAuthenticator = request.app.state.authenticator
    if not authenticator.configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="La autenticación de la API no está configurada",
        )

    if credentials is None:
        raise _unauthorized()

    principal = authenticator.authenticate(credentials.credentials)
    if principal is None:
        raise _unauthorized()
    if principal.role != required_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La identidad no tiene el rol requerido para esta operación",
        )
    return principal


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credencial Bearer ausente o inválida",
        headers={"WWW-Authenticate": "Bearer"},
    )
