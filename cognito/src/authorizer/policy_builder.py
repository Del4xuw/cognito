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
        policy: dict[str, Any] = {
            "principalId": principal_id,
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": effect,
                        "Resource": resource,
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

        return policy
