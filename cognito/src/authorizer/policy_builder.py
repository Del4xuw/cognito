"""IAM Policy Builder for API Gateway Lambda Authorizer responses."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger()


class PolicyBuilder:
    """Constructs the IAM policy document that API Gateway expects from a
    TOKEN-type Lambda Authorizer."""

    @staticmethod
    def build(
        principal_id: str,
        effect: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> dict:
        """Create a complete authorizer response.

        Args:
            principal_id: Unique identifier for the caller (typically ``sub``).
            effect: ``"Allow"`` or ``"Deny"``.
            resource: The ``methodArn`` from the authorizer event.
            context: Key/value pairs forwarded to the downstream Lambda via
                     ``event.requestContext.authorizer``.  Values **must** be
                     strings, numbers, or booleans (API Gateway limitation).

        Returns:
            Authorizer response dict with ``principalId``, ``policyDocument``,
            and optional ``context``.
        """
        # Extract base ARN and apply wildcard to allow all methods/resources
        # Format: arn:aws:execute-api:region:account:api-id/stage/method/resource
        # We want: arn:aws:execute-api:region:account:api-id/stage/*/*
        
        resource_parts = resource.split('/')
        if len(resource_parts) >= 2:
            # Build wildcard resource: arn:aws:execute-api:region:account:api-id/stage/*/*
            wildcard_resource = f"{resource_parts[0]}/{resource_parts[1]}/*/*"
            logger.info(f"Original resource: {resource}")
            logger.info(f"Wildcard resource: {wildcard_resource}")
        else:
            # Fallback to exact resource if parsing fails
            wildcard_resource = resource
            logger.warning(f"Unable to parse resource ARN, using exact match: {resource}")

        policy: dict[str, Any] = {
            "principalId": principal_id,
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": effect,
                        "Resource": wildcard_resource,  # ← Ahora usa wildcard
                    }
                ],
            },
        }

        if context:
            # API Gateway only supports str | int | float | bool in context
            sanitized: dict[str, str | int | float | bool] = {}
            for key, value in context.items():
                if isinstance(value, (str, int, float, bool)):
                    sanitized[key] = value
                else:
                    sanitized[key] = str(value)
            policy["context"] = sanitized

        logger.info(f"Generated policy for principal {principal_id}: {effect} on {wildcard_resource}")
        return policy