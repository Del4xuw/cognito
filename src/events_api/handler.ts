/**
 * Events API Lambda – CRUD operations with group-based visibility.
 *
 * Endpoints (all protected by the Lambda Authorizer):
 *   GET    /events            – list events (filtered by visibility)
 *   POST   /events            – create an event
 *   GET    /events/{eventId}  – get a single event
 *   DELETE /events/{eventId}  – delete an event (admins only via route rules)
 *
 * User context is injected by the authorizer into
 * `event.requestContext.authorizer`.
 */

import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  ScanCommand,
  PutCommand,
  GetCommand,
  DeleteCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  EventBridgeClient,
  PutEventsCommand,
} from "@aws-sdk/client-eventbridge";
import { randomUUID } from "crypto";

// ---------------------------------------------------------------------------
// AWS resources (initialised once per container)
// ---------------------------------------------------------------------------
const dynamoClient = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const eventBridgeClient = new EventBridgeClient({});

const EVENTS_TABLE: string = process.env.EVENTS_TABLE ?? "";
const EVENT_BUS_NAME: string = process.env.EVENTBRIDGE_BUS_NAME ?? "";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface EventItem {
  eventId: string;
  title: string;
  description: string;
  visibility: string;
  createdBy: string;
  createdAt: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Route requests to the appropriate CRUD handler.
 */
export const handler = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.info(
    JSON.stringify({
      message: "Events API invoked",
      request_id: context.awsRequestId,
      path: event.path,
      method: event.httpMethod,
    })
  );

  const path: string = event.path ?? "";
  const method: string = event.httpMethod ?? "";

  // Extract user context placed by the Lambda Authorizer
  const authCtx = event.requestContext?.authorizer ?? {};
  const username: string = (authCtx.username as string) ?? "unknown";
  const groupsStr: string = (authCtx.groups as string) ?? "";
  const userGroups: string[] = groupsStr
    .split(",")
    .map((g) => g.trim())
    .filter(Boolean);

  try {
    if (path === "/events" && method === "GET") {
      return await listEvents(userGroups, context);
    }
    if (path === "/events" && method === "POST") {
      return await createEvent(event, username, userGroups, context);
    }
    if (path.startsWith("/events/") && method === "GET") {
      const eventId = event.pathParameters?.eventId ?? "";
      return await getEvent(eventId, userGroups, context);
    }
    if (path.startsWith("/events/") && method === "DELETE") {
      const eventId = event.pathParameters?.eventId ?? "";
      return await deleteEvent(eventId, username, userGroups, context);
    }

    return response(404, { error: "Not Found" });
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "Unhandled error",
        error: error.message,
        request_id: context.awsRequestId,
      })
    );
    return response(500, {
      error: "Internal Server Error",
      message: "An unexpected error occurred",
    });
  }
};

// ---------------------------------------------------------------------------
// GET /events
// ---------------------------------------------------------------------------

/**
 * Return all events the caller is allowed to see.
 *
 * Visibility rules:
 *   admins    → all events (public, internal, private)
 *   deployers → public + internal
 *   viewers   → public only
 */
async function listEvents(
  userGroups: string[],
  context: Context
): Promise<APIGatewayProxyResult> {
  try {
    const items: Record<string, unknown>[] = [];
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
      const result = await docClient.send(
        new ScanCommand({
          TableName: EVENTS_TABLE,
          ExclusiveStartKey: lastEvaluatedKey,
        })
      );
      items.push(...(result.Items ?? []));
      lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    const filtered = filterByVisibility(items as EventItem[], userGroups);
    filtered.sort(
      (a, b) =>
        ((b as EventItem).createdAt ?? 0) - ((a as EventItem).createdAt ?? 0)
    );

    console.info(
      JSON.stringify({
        message: "Events listed",
        total: items.length,
        visible: filtered.length,
        request_id: context.awsRequestId,
      })
    );

    return response(200, { events: filtered, count: filtered.length });
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({ message: "Error listing events", error: error.message })
    );
    return response(500, {
      error: "Internal Server Error",
      message: "Failed to retrieve events",
    });
  }
}

// ---------------------------------------------------------------------------
// POST /events
// ---------------------------------------------------------------------------

/** Create a new event record in DynamoDB and publish to EventBridge. */
async function createEvent(
  event: APIGatewayProxyEvent,
  username: string,
  userGroups: string[],
  context: Context
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  if (!body) {
    return response(400, {
      error: "Bad Request",
      message: "Request body is required",
    });
  }

  const title: string = (body.title ?? "").trim();
  if (!title) {
    return response(400, {
      error: "Bad Request",
      message: "title is required",
    });
  }

  const description: string = (body.description ?? "").trim();
  const visibility: string = (body.visibility ?? "public").trim().toLowerCase();

  if (!["public", "internal", "private"].includes(visibility)) {
    return response(400, {
      error: "Bad Request",
      message: "visibility must be public, internal, or private",
    });
  }

  // Only admins may create private events
  if (visibility === "private" && !userGroups.includes("admins")) {
    return response(403, {
      error: "Forbidden",
      message: "Only admins can create private events",
    });
  }

  const eventId = randomUUID();
  const createdAt = Math.floor(Date.now() / 1000);

  const item: EventItem = {
    eventId,
    title,
    description,
    visibility,
    createdBy: username,
    createdAt,
  };

  try {
    await docClient.send(
      new PutCommand({
        TableName: EVENTS_TABLE,
        Item: item,
      })
    );
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "DynamoDB put_item failed",
        error: error.message,
      })
    );
    return response(500, {
      error: "Internal Server Error",
      message: "Failed to create event",
    });
  }

  await publishToEventBridge("EventCreated", item, username);

  console.info(
    JSON.stringify({
      message: "Event created",
      event_id: eventId,
      created_by: username,
      request_id: context.awsRequestId,
    })
  );

  return response(201, {
    message: "Event created successfully",
    event: item,
  });
}

// ---------------------------------------------------------------------------
// GET /events/{eventId}
// ---------------------------------------------------------------------------

/** Retrieve a single event by ID, respecting visibility rules. */
async function getEvent(
  eventId: string,
  userGroups: string[],
  context: Context
): Promise<APIGatewayProxyResult> {
  if (!eventId) {
    return response(400, {
      error: "Bad Request",
      message: "eventId is required",
    });
  }

  let item: Record<string, unknown> | undefined;
  try {
    const result = await docClient.send(
      new GetCommand({
        TableName: EVENTS_TABLE,
        Key: { eventId },
      })
    );
    item = result.Item;
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "DynamoDB get_item failed",
        error: error.message,
      })
    );
    return response(500, {
      error: "Internal Server Error",
      message: "Failed to retrieve event",
    });
  }

  if (!item) {
    return response(404, {
      error: "Not Found",
      message: `Event ${eventId} not found`,
    });
  }

  if (!canView(item as EventItem, userGroups)) {
    return response(403, {
      error: "Forbidden",
      message: "Insufficient permissions to view this event",
    });
  }

  return response(200, { event: item });
}

// ---------------------------------------------------------------------------
// DELETE /events/{eventId}
// ---------------------------------------------------------------------------

/**
 * Delete an event. Only admins can reach this endpoint via route rules,
 * but we add an explicit check as defence-in-depth.
 */
async function deleteEvent(
  eventId: string,
  username: string,
  userGroups: string[],
  context: Context
): Promise<APIGatewayProxyResult> {
  if (!eventId) {
    return response(400, {
      error: "Bad Request",
      message: "eventId is required",
    });
  }

  // Defence-in-depth: verify admin membership even though the authorizer
  // should have already denied non-admin users for DELETE.
  if (!userGroups.includes("admins")) {
    return response(403, {
      error: "Forbidden",
      message: "Only admins can delete events",
    });
  }

  let existingItem: Record<string, unknown> | undefined;
  try {
    const result = await docClient.send(
      new GetCommand({
        TableName: EVENTS_TABLE,
        Key: { eventId },
      })
    );
    existingItem = result.Item;
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "DynamoDB get_item failed",
        error: error.message,
      })
    );
    return response(500, {
      error: "Internal Server Error",
      message: "Failed to delete event",
    });
  }

  if (!existingItem) {
    return response(404, {
      error: "Not Found",
      message: `Event ${eventId} not found`,
    });
  }

  try {
    await docClient.send(
      new DeleteCommand({
        TableName: EVENTS_TABLE,
        Key: { eventId },
      })
    );
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "DynamoDB delete_item failed",
        error: error.message,
      })
    );
    return response(500, {
      error: "Internal Server Error",
      message: "Failed to delete event",
    });
  }

  await publishToEventBridge(
    "EventDeleted",
    { eventId, deletedBy: username },
    username
  );

  console.info(
    JSON.stringify({
      message: "Event deleted",
      event_id: eventId,
      deleted_by: username,
      request_id: context.awsRequestId,
    })
  );

  return response(200, {
    message: "Event deleted successfully",
    eventId,
  });
}

// ---------------------------------------------------------------------------
// Visibility helpers
// ---------------------------------------------------------------------------

/** Filter a list of events according to the caller's groups. */
function filterByVisibility(
  items: EventItem[],
  userGroups: string[]
): EventItem[] {
  if (userGroups.includes("admins")) {
    return items;
  }

  const result: EventItem[] = [];
  for (const item of items) {
    const vis = item.visibility ?? "public";
    if (vis === "public") {
      result.push(item);
    } else if (
      vis === "internal" &&
      (userGroups.includes("deployers") || userGroups.includes("admins"))
    ) {
      result.push(item);
    }
    // private events are only visible to admins (handled above)
  }
  return result;
}

/** Return `true` if the caller may view this specific event. */
function canView(item: EventItem, userGroups: string[]): boolean {
  const vis = item.visibility ?? "public";
  if (userGroups.includes("admins")) return true;
  if (vis === "public") return true;
  if (vis === "internal" && userGroups.includes("deployers")) return true;
  return false;
}

// ---------------------------------------------------------------------------
// EventBridge
// ---------------------------------------------------------------------------

/**
 * Best-effort publish to EventBridge. Failures are logged but do NOT
 * cause the API request to fail.
 */
async function publishToEventBridge(
  detailType: string,
  detail: Record<string, unknown>,
  username: string
): Promise<void> {
  try {
    await eventBridgeClient.send(
      new PutEventsCommand({
        Entries: [
          {
            Source: "events-api",
            DetailType: detailType,
            Detail: JSON.stringify(detail),
            EventBusName: EVENT_BUS_NAME,
          },
        ],
      })
    );
    console.info(
      JSON.stringify({
        message: "EventBridge publish OK",
        detail_type: detailType,
      })
    );
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "EventBridge publish failed",
        error: error.message,
        detail_type: detailType,
      })
    );
  }
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

/** Safely parse the JSON body from an API Gateway proxy event. */
function parseBody(
  event: APIGatewayProxyEvent
): Record<string, string> | null {
  try {
    const body = event.body;
    if (!body) {
      return null;
    }
    return typeof body === "string" ? JSON.parse(body) : body;
  } catch {
    return null;
  }
}

/** Build an API Gateway proxy-compatible response with CORS headers. */
function response(
  statusCode: number,
  body: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
      "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
    },
    body: JSON.stringify(body),
  };
}
