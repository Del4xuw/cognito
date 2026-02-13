"""Lambda Authorizer for API Gateway.

Validates JWT tokens issued by AWS Cognito, checks route-level permissions
in DynamoDB, and returns an IAM policy document (Allow / Deny).
"""

import json
import logging
import os
from typing import Any

import boto3

from jwt_validator import JWTValidator
from policy_builder import PolicyBuilder

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Initialise shared resources outside the handler (container reuse)
# ---------------------------------------------------------------------------
dynamodb = boto3.resource("dynamodb")
routes_table = dynamodb.Table(os.environ["ROUTES_SCOPES_TABLE"])

jwt_validator = JWTValidator(
    user_pool_id=os.environ["COGNITO_USER_POOL_ID"],
    region=os.environ["COGNITO_REGION"],
)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
def lambda_handler(event: dict, context: Any) -> dict:
    """Authorizer entry-point invoked by API Gateway (TOKEN type).

    Args:
        event: Contains ``authorizationToken`` and ``methodArn``.
        context: Lambda runtime context.

    Returns:
        IAM policy document with effect Allow or Deny plus user context.

    Raises:
        Exception: ``"Unauthorized"`` causes API Gateway to return 401.
    """
    logger.info(
        json.dumps(
            {
                "message": "Authorizer invoked",
                "request_id": context.aws_request_id,
                "method_arn": event.get("methodArn"),
            }
        )
    )

    try:
        # 1. Extract Bearer token ------------------------------------------------
        token = _extract_token(event)
        if not token:
            logger.warning("Missing or empty authorization token")
            raise Exception("Unauthorized")

        # 2. Validate JWT ---------------------------------------------------------
        claims = jwt_validator.validate_token(token)
        if not claims:
            logger.warning("JWT validation failed")
            raise Exception("Unauthorized")

        username: str = claims.get("username", claims.get("sub", "unknown"))
        groups: list[str] = claims.get("cognito:groups", [])

        logger.info(
            json.dumps(
                {"message": "Token validated", "username": username, "groups": groups}
            )
        )

        # 3. Parse the method ARN to determine route / method ---------------------
        method_arn: str = event["methodArn"]
        http_method, resource_path = _parse_method_arn(method_arn)
        normalized_path = _normalize_path(resource_path)

        # 4. Check permissions in DynamoDB ----------------------------------------
        is_authorized = _check_route_permission(normalized_path, http_method, groups)
        effect = "Allow" if is_authorized else "Deny"

        logger.info(
            json.dumps(
                {
                    "message": "Authorization decision",
                    "effect": effect,
                    "route": normalized_path,
                    "method": http_method,
                    "groups": groups,
                }
            )
        )

        # 5. Build IAM policy -----------------------------------------------------
        return PolicyBuilder.build(
            principal_id=claims.get("sub", "unknown"),
            effect=effect,
            resource=method_arn,
            context={
                "username": username,
                "groups": ",".join(groups) if groups else "",
                "sub": claims.get("sub", ""),
            },
        )

    except Exception as exc:
        # Re-raise the well-known "Unauthorized" sentinel so API GW returns 401
        if str(exc) == "Unauthorized":
            raise
        logger.error(
            json.dumps(
                {
                    "message": "Authorizer error",
                    "error": str(exc),
                    "request_id": context.aws_request_id,
                }
            )
        )
        raise Exception("Unauthorized") from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_token(event: dict) -> str | None:
    """Return the raw JWT from the ``authorizationToken`` field.

    Supports both ``Bearer <token>`` and bare token formats.
    """
    auth_token: str = event.get("authorizationToken", "")
    if auth_token.startswith("Bearer "):
        return auth_token[7:]
    return auth_token or None


def _parse_method_arn(method_arn: str) -> tuple[str, str]:
    """Extract HTTP method and resource path from the API Gateway method ARN.

    ARN format:
        arn:aws:execute-api:<region>:<account>:<api-id>/<stage>/<method>/<resource...>

    Returns:
        Tuple of (http_method, resource_path).
    """
    arn_parts = method_arn.split(":")
    api_parts = arn_parts[5].split("/")
    http_method = api_parts[2]
    resource_path = "/" + "/".join(api_parts[3:]) if len(api_parts) > 3 else "/"
    return http_method, resource_path


def _normalize_path(path: str) -> str:
    """Replace path-parameter segments with placeholders for DynamoDB look-up.

    Example: ``/events/abc-123`` → ``/events/{eventId}``
    """
    parts = path.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "events" and parts[1]:
        return "/events/{eventId}"
    return path


def _check_route_permission(
    route: str, method: str, user_groups: list[str]
) -> bool:
    """Query DynamoDB to see if any of *user_groups* may access *route*/*method*.

    Returns ``True`` when at least one user group appears in the route's
    ``allowed_groups`` list; ``False`` otherwise or on error.
    """
    try:
        response = routes_table.get_item(Key={"route": route, "method": method})
        item = response.get("Item")

        if not item:
            logger.warning(
                json.dumps(
                    {
                        "message": "Route not found in permissions table",
                        "route": route,
                        "method": method,
                    }
                )
            )
            return False

        allowed_groups: list[str] = item.get("allowed_groups", [])
        return bool(set(user_groups) & set(allowed_groups))

    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "message": "Error querying route permissions",
                    "error": str(exc),
                    "route": route,
                    "method": method,
                }
            )
        )
        return False
