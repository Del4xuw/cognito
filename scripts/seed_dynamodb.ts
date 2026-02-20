/**
 * Seed the Routes & Scopes DynamoDB table with authorization rules.
 *
 * Usage:
 *   npx ts-node scripts/seed_dynamodb.ts
 *   npx ts-node scripts/seed_dynamodb.ts --table my-routes-table
 *   npx ts-node scripts/seed_dynamodb.ts --region eu-west-1
 *
 * The script is idempotent – re-running it overwrites existing items.
 */

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";

// ---------------------------------------------------------------------------
// Default route permission rules
// ---------------------------------------------------------------------------
interface RouteRule {
  route: string;
  method: string;
  allowed_groups: string[];
  description: string;
}

const ROUTE_RULES: RouteRule[] = [
  {
    route: "/events",
    method: "GET",
    allowed_groups: ["viewers", "deployers", "admins"],
    description: "List all events (filtered by visibility per group)",
  },
  {
    route: "/events",
    method: "POST",
    allowed_groups: ["deployers", "admins"],
    description: "Create a new event",
  },
  {
    route: "/events/{eventId}",
    method: "GET",
    allowed_groups: ["viewers", "deployers", "admins"],
    description: "Get a single event by ID",
  },
  {
    route: "/events/{eventId}",
    method: "DELETE",
    allowed_groups: ["admins"],
    description: "Delete an event by ID",
  },
];

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------
function parseArgs(): { table: string; region: string } {
  const args = process.argv.slice(2);
  let table = "cognito-auth-system-routes-scopes";
  let region = "us-east-1";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--table" && args[i + 1]) {
      table = args[++i];
    } else if (args[i] === "--region" && args[i + 1]) {
      region = args[++i];
    }
  }
  return { table, region };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function seedRoutes(tableName: string, region: string): Promise<void> {
  const client = new DynamoDBClient({ region });
  const docClient = DynamoDBDocumentClient.from(client);

  console.log(`Seeding table '${tableName}' in ${region} ...`);

  for (const rule of ROUTE_RULES) {
    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: rule,
      })
    );
    const groups = JSON.stringify(rule.allowed_groups);
    console.log(
      `  ✓ ${rule.method.padEnd(6)} ${rule.route.padEnd(25)} → ${groups}`
    );
  }

  console.log(`\nDone – ${ROUTE_RULES.length} route rules written.`);
}

async function main(): Promise<void> {
  const { table, region } = parseArgs();

  try {
    await seedRoutes(table, region);
  } catch (exc) {
    const error = exc as Error;
    console.error(`\nERROR: ${error.message}`);
    process.exit(1);
  }
}

main();
