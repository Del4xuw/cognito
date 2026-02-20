/**
 * Auth API Lambda – public authentication endpoints.
 *
 * Provides:
 *   POST /auth/authorize  – exchange username + password for Cognito tokens
 *   POST /auth/refresh    – exchange a refresh token for new access/id tokens
 */

import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  InitiateAuthCommandOutput,
} from "@aws-sdk/client-cognito-identity-provider";

// ---------------------------------------------------------------------------
// AWS clients (initialised once per container)
// ---------------------------------------------------------------------------
const cognitoClient = new CognitoIdentityProviderClient({
  region: process.env.COGNITO_REGION ?? "us-east-1",
});
const CLIENT_ID: string = process.env.COGNITO_CLIENT_ID ?? "";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Route incoming requests to the appropriate handler.
 */
export const handler = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.info(
    JSON.stringify({
      message: "Auth API invoked",
      request_id: context.awsRequestId,
      path: event.path,
      method: event.httpMethod,
    })
  );

  const path = event.path ?? "";
  const method = event.httpMethod ?? "";

  if (path === "/auth/authorize" && method === "POST") {
    return handleAuthorize(event, context);
  }
  if (path === "/auth/refresh" && method === "POST") {
    return handleRefresh(event, context);
  }

  return response(404, {
    error: "Not Found",
    message: `${method} ${path} not found`,
  });
};

// ---------------------------------------------------------------------------
// POST /auth/authorize
// ---------------------------------------------------------------------------

/**
 * Authenticate a user with username + password via Cognito.
 *
 * Request body: { "username": "alice@example.com", "password": "P@ssw0rd!" }
 *
 * On success the response contains AccessToken, IdToken,
 * RefreshToken, ExpiresIn, and TokenType.
 */
async function handleAuthorize(
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  if (!body) {
    return response(400, {
      error: "Bad Request",
      message: "Request body is required",
    });
  }

  const username: string = (body.username ?? "").trim();
  const password: string = body.password ?? "";

  if (!username || !password) {
    return response(400, {
      error: "Bad Request",
      message: "username and password are required",
    });
  }

  try {
    const result: InitiateAuthCommandOutput = await cognitoClient.send(
      new InitiateAuthCommand({
        ClientId: CLIENT_ID,
        AuthFlow: "USER_PASSWORD_AUTH",
        AuthParameters: { USERNAME: username, PASSWORD: password },
      })
    );

    const auth = result.AuthenticationResult ?? {};

    console.info(
      JSON.stringify({
        message: "Authentication successful",
        username,
        request_id: context.awsRequestId,
      })
    );

    return response(200, {
      message: "Authentication successful",
      tokens: {
        AccessToken: auth.AccessToken ?? null,
        IdToken: auth.IdToken ?? null,
        RefreshToken: auth.RefreshToken ?? null,
        ExpiresIn: auth.ExpiresIn ?? null,
        TokenType: auth.TokenType ?? null,
      },
    });
  } catch (exc) {
    return handleCognitoError(exc, context, "authorize");
  }
}

// ---------------------------------------------------------------------------
// POST /auth/refresh
// ---------------------------------------------------------------------------

/**
 * Exchange a refresh token for new access and ID tokens.
 *
 * Request body: { "refresh_token": "eyJjdH..." }
 *
 * The response does not include a new RefreshToken – Cognito
 * returns only AccessToken, IdToken, ExpiresIn, and TokenType.
 */
async function handleRefresh(
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  if (!body) {
    return response(400, {
      error: "Bad Request",
      message: "Request body is required",
    });
  }

  const refreshToken: string = (body.refresh_token ?? "").trim();
  if (!refreshToken) {
    return response(400, {
      error: "Bad Request",
      message: "refresh_token is required",
    });
  }

  try {
    const result: InitiateAuthCommandOutput = await cognitoClient.send(
      new InitiateAuthCommand({
        ClientId: CLIENT_ID,
        AuthFlow: "REFRESH_TOKEN_AUTH",
        AuthParameters: { REFRESH_TOKEN: refreshToken },
      })
    );

    const auth = result.AuthenticationResult ?? {};

    console.info(
      JSON.stringify({
        message: "Token refresh successful",
        request_id: context.awsRequestId,
      })
    );

    return response(200, {
      message: "Token refresh successful",
      tokens: {
        AccessToken: auth.AccessToken ?? null,
        IdToken: auth.IdToken ?? null,
        ExpiresIn: auth.ExpiresIn ?? null,
        TokenType: auth.TokenType ?? null,
      },
    });
  } catch (exc) {
    return handleCognitoError(exc, context, "refresh");
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Translate Cognito errors into an appropriate HTTP response.
 */
function handleCognitoError(
  exc: unknown,
  context: Context,
  operation: string
): APIGatewayProxyResult {
  const error = exc as Error & { name?: string; __type?: string };
  const errorCode: string = error.name ?? error.__type ?? "UnknownError";
  const errorMsg: string = error.message ?? "Unknown error";

  console.warn(
    JSON.stringify({
      message: `${operation} failed`,
      error_code: errorCode,
      error_message: errorMsg,
      request_id: context.awsRequestId,
    })
  );

  const mapping: Record<string, [number, string]> = {
    NotAuthorizedException: [401, "Invalid credentials or expired token"],
    UserNotFoundException: [401, "Invalid credentials"],
    UserNotConfirmedException: [403, "User account is not confirmed"],
    PasswordResetRequiredException: [403, "Password reset is required"],
  };

  const match = mapping[errorCode];
  if (match) {
    const [status, message] = match;
    return response(status, { error: "AuthError", message });
  }

  console.error(
    JSON.stringify({
      message: `Unexpected error in ${operation}`,
      error: errorMsg,
      request_id: context.awsRequestId,
    })
  );
  return response(500, {
    error: "Internal Server Error",
    message: "An unexpected error occurred",
  });
}

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
      "Access-Control-Allow-Methods": "POST,OPTIONS",
    },
    body: JSON.stringify(body),
  };
}
