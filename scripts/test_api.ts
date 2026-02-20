/**
 * End-to-end API testing script for the Cognito Auth System.
 *
 * Usage:
 *   npx ts-node scripts/test_api.ts --api-url https://abc123.execute-api.us-east-1.amazonaws.com/dev \
 *                                    --username admin@example.com --password 'P@ssw0rd!'
 *
 * The script exercises:
 *   1. Login flow (POST /auth/authorize)
 *   2. Token refresh (POST /auth/refresh)
 *   3. Protected endpoints (GET/POST/DELETE /events)
 *   4. Authorization failure scenarios
 */

// ---------------------------------------------------------------------------
// Colours for terminal output
// ---------------------------------------------------------------------------
const GREEN = "\x1b[92m";
const RED = "\x1b[91m";
const YELLOW = "\x1b[93m";
const RESET = "\x1b[0m";

function ok(msg: string): void {
  console.log(`  ${GREEN}✓ PASS${RESET}  ${msg}`);
}

function fail(msg: string): void {
  console.log(`  ${RED}✗ FAIL${RESET}  ${msg}`);
}

function info(msg: string): void {
  console.log(`  ${YELLOW}ℹ INFO${RESET}  ${msg}`);
}

// ---------------------------------------------------------------------------
// HTTP helper (uses Node.js built-in fetch, available in Node 18+)
// ---------------------------------------------------------------------------
interface FetchResult {
  status: number;
  body: Record<string, unknown>;
}

async function request(
  url: string,
  options: RequestInit = {}
): Promise<FetchResult> {
  const resp = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    },
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await resp.json()) as Record<string, unknown>;
  return { status: resp.status, body };
}

function authHeader(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

interface Tokens {
  AccessToken?: string;
  IdToken?: string;
  RefreshToken?: string;
  ExpiresIn?: number;
  TokenType?: string;
}

async function login(
  apiUrl: string,
  username: string,
  password: string
): Promise<Tokens | null> {
  const url = `${apiUrl.replace(/\/$/, "")}/auth/authorize`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`POST ${url}`);
  console.log(`${"=".repeat(60)}`);

  const { status, body } = await request(url, {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  if (status === 200) {
    const tokens = body.tokens as Tokens;
    ok(`Login successful (HTTP ${status})`);
    info(`AccessToken: ${tokens.AccessToken?.substring(0, 40)}...`);
    return tokens;
  } else {
    fail(`Login failed (HTTP ${status}): ${(body as Record<string, unknown>).message}`);
    return null;
  }
}

async function refreshTokens(
  apiUrl: string,
  refreshToken: string
): Promise<Tokens | null> {
  const url = `${apiUrl.replace(/\/$/, "")}/auth/refresh`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`POST ${url}`);
  console.log(`${"=".repeat(60)}`);

  const { status, body } = await request(url, {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (status === 200) {
    ok(`Token refresh successful (HTTP ${status})`);
    return body.tokens as Tokens;
  } else {
    fail(`Token refresh failed (HTTP ${status}): ${(body as Record<string, unknown>).message}`);
    return null;
  }
}

async function testListEvents(
  apiUrl: string,
  accessToken: string
): Promise<void> {
  const url = `${apiUrl.replace(/\/$/, "")}/events`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`GET ${url}`);
  console.log(`${"=".repeat(60)}`);

  const { status, body } = await request(url, {
    headers: authHeader(accessToken),
  });

  if (status === 200) {
    ok(`List events (HTTP ${status}) – ${body.count ?? 0} event(s)`);
  } else {
    fail(`List events failed (HTTP ${status}): ${JSON.stringify(body)}`);
  }
}

async function testCreateEvent(
  apiUrl: string,
  accessToken: string
): Promise<string | null> {
  const url = `${apiUrl.replace(/\/$/, "")}/events`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`POST ${url}`);
  console.log(`${"=".repeat(60)}`);

  const payload = {
    title: "Test Deployment v2.1",
    description: "Automated test event created by test_api.ts",
    visibility: "public",
  };

  const { status, body } = await request(url, {
    method: "POST",
    headers: authHeader(accessToken),
    body: JSON.stringify(payload),
  });

  if (status === 201) {
    const eventData = body.event as Record<string, unknown>;
    const eventId = eventData?.eventId as string;
    ok(`Event created (HTTP ${status}) – eventId=${eventId}`);
    return eventId;
  } else {
    fail(`Create event failed (HTTP ${status}): ${JSON.stringify(body)}`);
    return null;
  }
}

async function testGetEvent(
  apiUrl: string,
  accessToken: string,
  eventId: string
): Promise<void> {
  const url = `${apiUrl.replace(/\/$/, "")}/events/${eventId}`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`GET ${url}`);
  console.log(`${"=".repeat(60)}`);

  const { status, body } = await request(url, {
    headers: authHeader(accessToken),
  });

  if (status === 200) {
    const eventData = body.event as Record<string, unknown>;
    ok(`Get event (HTTP ${status}) – title=${eventData?.title}`);
  } else {
    fail(`Get event failed (HTTP ${status}): ${JSON.stringify(body)}`);
  }
}

async function testDeleteEvent(
  apiUrl: string,
  accessToken: string,
  eventId: string
): Promise<void> {
  const url = `${apiUrl.replace(/\/$/, "")}/events/${eventId}`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`DELETE ${url}`);
  console.log(`${"=".repeat(60)}`);

  const { status, body } = await request(url, {
    method: "DELETE",
    headers: authHeader(accessToken),
  });

  if (status === 200) {
    ok(`Event deleted (HTTP ${status})`);
  } else if (status === 403) {
    info(
      `Delete denied (HTTP 403) – expected if user is not admin: ${(body as Record<string, unknown>).message}`
    );
  } else {
    fail(`Delete event failed (HTTP ${status}): ${JSON.stringify(body)}`);
  }
}

async function testUnauthorizedAccess(apiUrl: string): Promise<void> {
  const url = `${apiUrl.replace(/\/$/, "")}/events`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`GET ${url}  (no Authorization header)`);
  console.log(`${"=".repeat(60)}`);

  const { status } = await request(url);

  if (status === 401) {
    ok(`Correctly rejected (HTTP 401)`);
  } else {
    fail(`Expected 401 but got HTTP ${status}`);
  }
}

async function testInvalidToken(apiUrl: string): Promise<void> {
  const url = `${apiUrl.replace(/\/$/, "")}/events`;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`GET ${url}  (invalid token)`);
  console.log(`${"=".repeat(60)}`);

  const { status } = await request(url, {
    headers: { Authorization: "Bearer invalid.token.here" },
  });

  if (status === 401 || status === 403) {
    ok(`Correctly rejected (HTTP ${status})`);
  } else {
    fail(`Expected 401/403 but got HTTP ${status}`);
  }
}

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------
function parseArgs(): { apiUrl: string; username: string; password: string } {
  const args = process.argv.slice(2);
  let apiUrl = "";
  let username = "";
  let password = "";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--api-url" && args[i + 1]) {
      apiUrl = args[++i];
    } else if (args[i] === "--username" && args[i + 1]) {
      username = args[++i];
    } else if (args[i] === "--password" && args[i + 1]) {
      password = args[++i];
    }
  }

  if (!apiUrl || !username || !password) {
    console.error(
      "Usage: npx ts-node test_api.ts --api-url <URL> --username <USER> --password <PASS>"
    );
    process.exit(1);
  }

  return { apiUrl, username, password };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const { apiUrl, username, password } = parseArgs();

  console.log(`\n${"=".repeat(60)}`);
  console.log("  Cognito Auth System – End-to-End Tests");
  console.log(`${"=".repeat(60)}`);

  // 1. Login
  const tokens = await login(apiUrl, username, password);
  if (!tokens) {
    console.log("\nAborting – login failed.");
    process.exit(1);
  }

  let accessToken: string = tokens.AccessToken!;

  // 2. Refresh
  if (tokens.RefreshToken) {
    const newTokens = await refreshTokens(apiUrl, tokens.RefreshToken);
    if (newTokens?.AccessToken) {
      accessToken = newTokens.AccessToken;
      info("Using refreshed AccessToken for remaining tests");
    }
  }

  // 3. List events
  await testListEvents(apiUrl, accessToken);

  // 4. Create event
  const eventId = await testCreateEvent(apiUrl, accessToken);

  // 5. Get single event
  if (eventId) {
    await testGetEvent(apiUrl, accessToken, eventId);
  }

  // 6. Delete event
  if (eventId) {
    await testDeleteEvent(apiUrl, accessToken, eventId);
  }

  // 7. Unauthorized access (no token)
  await testUnauthorizedAccess(apiUrl);

  // 8. Invalid token
  await testInvalidToken(apiUrl);

  console.log(`\n${"=".repeat(60)}`);
  console.log("  Tests complete");
  console.log(`${"=".repeat(60)}\n`);
}

main();
