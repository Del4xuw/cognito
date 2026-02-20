/**
 * Lambda Authorizer for API Gateway.
 *
 * Validates JWT tokens issued by AWS Cognito, checks route-level permissions
 * in DynamoDB, and returns an IAM policy document (Allow / Deny).
 */

import {
  APIGatewayTokenAuthorizerEvent,
  APIGatewayAuthorizerResult,
  Context,
  StatementEffect,
} from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import { JWTValidator, CognitoClaims } from "./jwtValidator";
import { PolicyBuilder } from "./policyBuilder";

// ---------------------------------------------------------------------------
// Initialise shared resources outside the handler (container reuse)
// ---------------------------------------------------------------------------
const dynamoClient = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const ROUTES_SCOPES_TABLE = process.env.ROUTES_SCOPES_TABLE!;

const jwtValidator = new JWTValidator(
  process.env.COGNITO_USER_POOL_ID!,
  process.env.COGNITO_REGION!
);

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Authorizer entry-point invoked by API Gateway (TOKEN type).
 *
 * @param event - Contains `authorizationToken` and `methodArn`.
 * @param context - Lambda runtime context.
 * @returns IAM policy document with effect Allow or Deny plus user context.
 * @throws "Unauthorized" causes API Gateway to return 401.
 */
export const handler = async (
  event: APIGatewayTokenAuthorizerEvent,
  context: Context
): Promise<APIGatewayAuthorizerResult> => {
  console.info(
    JSON.stringify({
      message: "Authorizer invoked",
      request_id: context.awsRequestId,
      method_arn: event.methodArn,
    })
  );

  try {
    // 1. Extract Bearer token ------------------------------------------------
    const token = extractToken(event);
    if (!token) {
      console.warn("Missing or empty authorization token");
      throw new Error("Unauthorized");
    }

    // 2. Validate JWT ---------------------------------------------------------
    const claims = await jwtValidator.validateToken(token);
    if (!claims) {
      console.warn("JWT validation failed");
      throw new Error("Unauthorized");
    }

    const username: string = claims.username ?? claims.sub ?? "unknown";
    const groups: string[] = claims["cognito:groups"] ?? [];

    console.info(
      JSON.stringify({ message: "Token validated", username, groups })
    );

    // 3. Parse the method ARN to determine route / method ---------------------
    const methodArn: string = event.methodArn;
    const [httpMethod, resourcePath] = parseMethodArn(methodArn);
    const normalizedPath = normalizePath(resourcePath);

    // 4. Check permissions in DynamoDB ----------------------------------------
    const isAuthorized = await checkRoutePermission(
      normalizedPath,
      httpMethod,
      groups
    );
    const effect: StatementEffect = isAuthorized ? "Allow" : "Deny";

    console.info(
      JSON.stringify({
        message: "Authorization decision",
        effect,
        route: normalizedPath,
        method: httpMethod,
        groups,
      })
    );

    // 5. Build IAM policy -----------------------------------------------------
    return PolicyBuilder.build(claims.sub ?? "unknown", effect, methodArn, {
      username,
      groups: groups.length > 0 ? groups.join(",") : "",
      sub: claims.sub ?? "",
    });
  } catch (exc) {
    const error = exc as Error;
    // Re-raise the well-known "Unauthorized" sentinel so API GW returns 401
    if (error.message === "Unauthorized") {
      throw error;
    }
    console.error(
      JSON.stringify({
        message: "Authorizer error",
        error: error.message,
        request_id: context.awsRequestId,
      })
    );
    throw new Error("Unauthorized");
  }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return the raw JWT from the `authorizationToken` field.
 * Supports both `Bearer <token>` and bare token formats.
 */
function extractToken(
  event: APIGatewayTokenAuthorizerEvent
): string | null {
  const authToken: string = event.authorizationToken ?? "";
  if (authToken.startsWith("Bearer ")) {
    return authToken.substring(7);
  }
  return authToken || null;
}

/**
 * Extract HTTP method and resource path from the API Gateway method ARN.
 *
 * ARN format:
 *   arn:aws:execute-api:<region>:<account>:<api-id>/<stage>/<method>/<resource...>
 *
 * @returns Tuple of [httpMethod, resourcePath].
 */
function parseMethodArn(methodArn: string): [string, string] {
  const arnParts = methodArn.split(":");
  const apiParts = arnParts[5].split("/");
  const httpMethod = apiParts[2];
  const resourcePath =
    apiParts.length > 3 ? "/" + apiParts.slice(3).join("/") : "/";
  return [httpMethod, resourcePath];
}

/**
 * Replace path-parameter segments with placeholders for DynamoDB look-up.
 *
 * Example: `/events/abc-123` → `/events/{eventId}`
 */
function normalizePath(path: string): string {
  const parts = path
    .replace(/^\/|\/$/g, "")
    .split("/");
  if (parts.length >= 2 && parts[0] === "events" && parts[1]) {
    return "/events/{eventId}";
  }
  return path;
}

/**
 * Query DynamoDB to see if any of `userGroups` may access `route`/`method`.
 *
 * @returns `true` when at least one user group appears in the route's
 * `allowed_groups` list; `false` otherwise or on error.
 */
async function checkRoutePermission(
  route: string,
  method: string,
  userGroups: string[]
): Promise<boolean> {
  try {
    const response = await docClient.send(
      new GetCommand({
        TableName: ROUTES_SCOPES_TABLE,
        Key: { route, method },
      })
    );

    const item = response.Item;
    if (!item) {
      console.warn(
        JSON.stringify({
          message: "Route not found in permissions table",
          route,
          method,
        })
      );
      return false;
    }

    const allowedGroups: string[] = (item.allowed_groups as string[]) ?? [];
    const userGroupSet = new Set(userGroups);
    return allowedGroups.some((g) => userGroupSet.has(g));
  } catch (exc) {
    const error = exc as Error;
    console.error(
      JSON.stringify({
        message: "Error querying route permissions",
        error: error.message,
        route,
        method,
      })
    );
    return false;
  }
}
