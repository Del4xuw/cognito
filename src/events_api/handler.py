"""Events API Lambda – CRUD operations with group-based visibility.

Endpoints (all protected by the Lambda Authorizer):
    GET    /events            – list events (filtered by visibility)
    POST   /events            – create an event
    GET    /events/{eventId}  – get a single event
    DELETE /events/{eventId}  – delete an event (admins only via route rules)

User context is injected by the authorizer into
``event["requestContext"]["authorizer"]``.
"""

import json
import logging
import os
import time
import uuid
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# AWS resources (initialised once per container)
# ---------------------------------------------------------------------------
dynamodb = boto3.resource("dynamodb")
events_table = dynamodb.Table(os.environ.get("EVENTS_TABLE", ""))
eventbridge = boto3.client("events")
EVENT_BUS_NAME: str = os.environ.get("EVENTBRIDGE_BUS_NAME", "")


# ---------------------------------------------------------------------------
# JSON helper for DynamoDB Decimal types
# ---------------------------------------------------------------------------
class _DecimalEncoder(json.JSONEncoder):
    """Encode ``Decimal`` values returned by DynamoDB as int or float."""

    def default(self, o: Any) -> Any:  # noqa: ANN401
        if isinstance(o, Decimal):
            return int(o) if o % 1 == 0 else float(o)
        return super().default(o)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
def lambda_handler(event: dict, context: Any) -> dict:
    """Route requests to the appropriate CRUD handler.

    Args:
        event: API Gateway proxy integration event.
        context: Lambda runtime context.

    Returns:
        API Gateway proxy response ``dict``.
    """
    logger.info(
        json.dumps(
            {
                "message": "Events API invoked",
                "request_id": context.aws_request_id,
                "path": event.get("path"),
                "method": event.get("httpMethod"),
            }
        )
    )

    path: str = event.get("path", "")
    method: str = event.get("httpMethod", "")

    # Extract user context placed by the Lambda Authorizer
    auth_ctx = event.get("requestContext", {}).get("authorizer", {})
    username: str = auth_ctx.get("username", "unknown")
    groups_str: str = auth_ctx.get("groups", "")
    user_groups: list[str] = [g.strip() for g in groups_str.split(",") if g.strip()]

    try:
        if path == "/events" and method == "GET":
            return _list_events(user_groups, context)
        if path == "/events" and method == "POST":
            return _create_event(event, username, user_groups, context)
        if path.startswith("/events/") and method == "GET":
            event_id = (event.get("pathParameters") or {}).get("eventId", "")
            return _get_event(event_id, user_groups, context)
        if path.startswith("/events/") and method == "DELETE":
            event_id = (event.get("pathParameters") or {}).get("eventId", "")
            return _delete_event(event_id, username, user_groups, context)

        return _response(404, {"error": "Not Found"})

    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "message": "Unhandled error",
                    "error": str(exc),
                    "request_id": context.aws_request_id,
                }
            )
        )
        return _response(500, {"error": "Internal Server Error", "message": "An unexpected error occurred"})


# ---------------------------------------------------------------------------
# GET /events
# ---------------------------------------------------------------------------
def _list_events(user_groups: list[str], context: Any) -> dict:
    """Return all events the caller is allowed to see.

    Visibility rules:
        * **admins** → all events (public, internal, private)
        * **deployers** → public + internal
        * **viewers** → public only
    """
    try:
        items: list[dict] = []
        response = events_table.scan()
        items.extend(response.get("Items", []))

        while "LastEvaluatedKey" in response:
            response = events_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        filtered = _filter_by_visibility(items, user_groups)
        filtered.sort(key=lambda x: x.get("createdAt", 0), reverse=True)

        logger.info(
            json.dumps(
                {
                    "message": "Events listed",
                    "total": len(items),
                    "visible": len(filtered),
                    "request_id": context.aws_request_id,
                }
            )
        )

        return _response(200, {"events": filtered, "count": len(filtered)})

    except Exception as exc:
        logger.error(json.dumps({"message": "Error listing events", "error": str(exc)}))
        return _response(500, {"error": "Internal Server Error", "message": "Failed to retrieve events"})


# ---------------------------------------------------------------------------
# POST /events
# ---------------------------------------------------------------------------
def _create_event(
    event: dict, username: str, user_groups: list[str], context: Any
) -> dict:
    """Create a new event record in DynamoDB and publish to EventBridge."""
    body = _parse_body(event)
    if not body:
        return _response(400, {"error": "Bad Request", "message": "Request body is required"})

    title: str = body.get("title", "").strip()
    if not title:
        return _response(400, {"error": "Bad Request", "message": "title is required"})

    description: str = body.get("description", "").strip()
    visibility: str = body.get("visibility", "public").strip().lower()

    if visibility not in ("public", "internal", "private"):
        return _response(400, {"error": "Bad Request", "message": "visibility must be public, internal, or private"})

    # Only admins may create private events
    if visibility == "private" and "admins" not in user_groups:
        return _response(403, {"error": "Forbidden", "message": "Only admins can create private events"})

    event_id = str(uuid.uuid4())
    created_at = int(time.time())

    item: dict[str, Any] = {
        "eventId": event_id,
        "title": title,
        "description": description,
        "visibility": visibility,
        "createdBy": username,
        "createdAt": created_at,
    }

    try:
        events_table.put_item(Item=item)
    except ClientError as exc:
        logger.error(json.dumps({"message": "DynamoDB put_item failed", "error": str(exc)}))
        return _response(500, {"error": "Internal Server Error", "message": "Failed to create event"})

    _publish_to_eventbridge("EventCreated", item, username)

    logger.info(
        json.dumps(
            {
                "message": "Event created",
                "event_id": event_id,
                "created_by": username,
                "request_id": context.aws_request_id,
            }
        )
    )

    return _response(201, {"message": "Event created successfully", "event": item})


# ---------------------------------------------------------------------------
# GET /events/{eventId}
# ---------------------------------------------------------------------------
def _get_event(event_id: str, user_groups: list[str], context: Any) -> dict:
    """Retrieve a single event by ID, respecting visibility rules."""
    if not event_id:
        return _response(400, {"error": "Bad Request", "message": "eventId is required"})

    try:
        result = events_table.get_item(Key={"eventId": event_id})
    except ClientError as exc:
        logger.error(json.dumps({"message": "DynamoDB get_item failed", "error": str(exc)}))
        return _response(500, {"error": "Internal Server Error", "message": "Failed to retrieve event"})

    item = result.get("Item")
    if not item:
        return _response(404, {"error": "Not Found", "message": f"Event {event_id} not found"})

    if not _can_view(item, user_groups):
        return _response(403, {"error": "Forbidden", "message": "Insufficient permissions to view this event"})

    return _response(200, {"event": item})


# ---------------------------------------------------------------------------
# DELETE /events/{eventId}
# ---------------------------------------------------------------------------
def _delete_event(
    event_id: str, username: str, user_groups: list[str], context: Any
) -> dict:
    """Delete an event. Only admins can reach this endpoint via route rules,
    but we add an explicit check as defence-in-depth."""
    if not event_id:
        return _response(400, {"error": "Bad Request", "message": "eventId is required"})

    # Defence-in-depth: verify admin membership even though the authorizer
    # should have already denied non-admin users for DELETE.
    if "admins" not in user_groups:
        return _response(403, {"error": "Forbidden", "message": "Only admins can delete events"})

    try:
        result = events_table.get_item(Key={"eventId": event_id})
    except ClientError as exc:
        logger.error(json.dumps({"message": "DynamoDB get_item failed", "error": str(exc)}))
        return _response(500, {"error": "Internal Server Error", "message": "Failed to delete event"})

    if not result.get("Item"):
        return _response(404, {"error": "Not Found", "message": f"Event {event_id} not found"})

    try:
        events_table.delete_item(Key={"eventId": event_id})
    except ClientError as exc:
        logger.error(json.dumps({"message": "DynamoDB delete_item failed", "error": str(exc)}))
        return _response(500, {"error": "Internal Server Error", "message": "Failed to delete event"})

    _publish_to_eventbridge(
        "EventDeleted",
        {"eventId": event_id, "deletedBy": username},
        username,
    )

    logger.info(
        json.dumps(
            {
                "message": "Event deleted",
                "event_id": event_id,
                "deleted_by": username,
                "request_id": context.aws_request_id,
            }
        )
    )

    return _response(200, {"message": "Event deleted successfully", "eventId": event_id})


# ---------------------------------------------------------------------------
# Visibility helpers
# ---------------------------------------------------------------------------
def _filter_by_visibility(items: list[dict], user_groups: list[str]) -> list[dict]:
    """Filter a list of events according to the caller's groups."""
    if "admins" in user_groups:
        return items

    result: list[dict] = []
    for item in items:
        vis = item.get("visibility", "public")
        if vis == "public":
            result.append(item)
        elif vis == "internal" and ("deployers" in user_groups or "admins" in user_groups):
            result.append(item)
        # private events are only visible to admins (handled above)
    return result


def _can_view(item: dict, user_groups: list[str]) -> bool:
    """Return ``True`` if the caller may view this specific event."""
    vis = item.get("visibility", "public")
    if "admins" in user_groups:
        return True
    if vis == "public":
        return True
    if vis == "internal" and "deployers" in user_groups:
        return True
    return False


# ---------------------------------------------------------------------------
# EventBridge
# ---------------------------------------------------------------------------
def _publish_to_eventbridge(detail_type: str, detail: dict, username: str) -> None:
    """Best-effort publish to EventBridge. Failures are logged but do NOT
    cause the API request to fail."""
    try:
        eventbridge.put_events(
            Entries=[
                {
                    "Source": "events-api",
                    "DetailType": detail_type,
                    "Detail": json.dumps(detail, cls=_DecimalEncoder),
                    "EventBusName": EVENT_BUS_NAME,
                }
            ]
        )
        logger.info(json.dumps({"message": "EventBridge publish OK", "detail_type": detail_type}))
    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "message": "EventBridge publish failed",
                    "error": str(exc),
                    "detail_type": detail_type,
                }
            )
        )


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
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
            "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
        },
        "body": json.dumps(body, cls=_DecimalEncoder),
    }
