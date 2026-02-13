"""Auth API Lambda – public authentication endpoints.

Provides:
    POST /auth/authorize  – exchange username + password for Cognito tokens
    POST /auth/refresh    – exchange a refresh token for new access/id tokens
"""

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# AWS clients (initialised once per container)
# ---------------------------------------------------------------------------
cognito_client = boto3.client(
    "cognito-idp",
    region_name=os.environ.get("COGNITO_REGION", "us-east-1"),
)
CLIENT_ID: str = os.environ.get("COGNITO_CLIENT_ID", "")


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
def lambda_handler(event: dict, context: Any) -> dict:
    """Route incoming requests to the appropriate handler.

    Args:
        event: API Gateway proxy integration event.
        context: Lambda runtime context.

    Returns:
        API Gateway proxy response ``dict``.
    """
    logger.info(
        json.dumps(
            {
                "message": "Auth API invoked",
                "request_id": context.aws_request_id,
                "path": event.get("path"),
                "method": event.get("httpMethod"),
            }
        )
    )

    path = event.get("path", "")
    method = event.get("httpMethod", "")

    if path == "/auth/authorize" and method == "POST":
        return _handle_authorize(event, context)
    if path == "/auth/refresh" and method == "POST":
        return _handle_refresh(event, context)

    return _response(404, {"error": "Not Found", "message": f"{method} {path} not found"})


# ---------------------------------------------------------------------------
# POST /auth/authorize
# ---------------------------------------------------------------------------
def _handle_authorize(event: dict, context: Any) -> dict:
    """Authenticate a user with username + password via Cognito.

    Request body::

        {"username": "alice@example.com", "password": "P@ssw0rd!"}

    On success the response contains ``AccessToken``, ``IdToken``,
    ``RefreshToken``, ``ExpiresIn``, and ``TokenType``.
    """
    body = _parse_body(event)
    if not body:
        return _response(400, {"error": "Bad Request", "message": "Request body is required"})

    username: str = body.get("username", "").strip()
    password: str = body.get("password", "")

    if not username or not password:
        return _response(400, {"error": "Bad Request", "message": "username and password are required"})

    try:
        result = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )

        auth = result.get("AuthenticationResult", {})

        logger.info(
            json.dumps(
                {
                    "message": "Authentication successful",
                    "username": username,
                    "request_id": context.aws_request_id,
                }
            )
        )

        return _response(
            200,
            {
                "message": "Authentication successful",
                "tokens": {
                    "AccessToken": auth.get("AccessToken"),
                    "IdToken": auth.get("IdToken"),
                    "RefreshToken": auth.get("RefreshToken"),
                    "ExpiresIn": auth.get("ExpiresIn"),
                    "TokenType": auth.get("TokenType"),
                },
            },
        )

    except ClientError as exc:
        return _handle_cognito_error(exc, context, "authorize")
    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "message": "Unexpected error in authorize",
                    "error": str(exc),
                    "request_id": context.aws_request_id,
                }
            )
        )
        return _response(500, {"error": "Internal Server Error", "message": "An unexpected error occurred"})


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------
def _handle_refresh(event: dict, context: Any) -> dict:
    """Exchange a refresh token for new access and ID tokens.

    Request body::

        {"refresh_token": "eyJjdH..."}

    The response does **not** include a new ``RefreshToken`` – Cognito
    returns only ``AccessToken``, ``IdToken``, ``ExpiresIn``, and
    ``TokenType``.
    """
    body = _parse_body(event)
    if not body:
        return _response(400, {"error": "Bad Request", "message": "Request body is required"})

    refresh_token: str = body.get("refresh_token", "").strip()
    if not refresh_token:
        return _response(400, {"error": "Bad Request", "message": "refresh_token is required"})

    try:
        result = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )

        auth = result.get("AuthenticationResult", {})

        logger.info(
            json.dumps(
                {
                    "message": "Token refresh successful",
                    "request_id": context.aws_request_id,
                }
            )
        )

        return _response(
            200,
            {
                "message": "Token refresh successful",
                "tokens": {
                    "AccessToken": auth.get("AccessToken"),
                    "IdToken": auth.get("IdToken"),
                    "ExpiresIn": auth.get("ExpiresIn"),
                    "TokenType": auth.get("TokenType"),
                },
            },
        )

    except ClientError as exc:
        return _handle_cognito_error(exc, context, "refresh")
    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "message": "Unexpected error in refresh",
                    "error": str(exc),
                    "request_id": context.aws_request_id,
                }
            )
        )
        return _response(500, {"error": "Internal Server Error", "message": "An unexpected error occurred"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _handle_cognito_error(exc: ClientError, context: Any, operation: str) -> dict:
    """Translate Cognito ClientError into an appropriate HTTP response."""
    error_code: str = exc.response["Error"]["Code"]
    error_msg: str = exc.response["Error"]["Message"]

    logger.warning(
        json.dumps(
            {
                "message": f"{operation} failed",
                "error_code": error_code,
                "error_message": error_msg,
                "request_id": context.aws_request_id,
            }
        )
    )

    mapping: dict[str, tuple[int, str]] = {
        "NotAuthorizedException": (401, "Invalid credentials or expired token"),
        "UserNotFoundException": (401, "Invalid credentials"),
        "UserNotConfirmedException": (403, "User account is not confirmed"),
        "PasswordResetRequiredException": (403, "Password reset is required"),
    }

    status, message = mapping.get(error_code, (500, "Authentication service error"))
    return _response(status, {"error": "AuthError", "message": message})


def _parse_body(event: dict) -> dict | None:
    """Safely parse the JSON body from an API Gateway proxy event."""
    try:
        body = event.get("body", "")
        if not body:
            return None
        return json.loads(body) if isinstance(body, str) else body
    except (json.JSONDecodeError, TypeError):
        return None


def _response(status_code: int, body: dict) -> dict:
    """Build an API Gateway proxy-compatible response with CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        },
        "body": json.dumps(body),
    }
