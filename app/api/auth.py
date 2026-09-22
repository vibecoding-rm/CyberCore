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
    if principal.role != "operator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La identidad no tiene permiso para ejecutar herramientas",
        )
    return principal


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credencial Bearer ausente o inválida",
        headers={"WWW-Authenticate": "Bearer"},
    )
