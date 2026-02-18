# Cognito Serverless Authorization System

A production-ready, serverless authorization system built on AWS using SAM.  
It integrates an **existing** Cognito User Pool with API Gateway, a custom Lambda
Authorizer, and DynamoDB-backed route permission rules.

---

## Architecture

```
                         ┌──────────────────────┐
                         │   Cognito User Pool   │  (existing)
                         │  us-east-1_Ibp76ZpqU  │
                         └──────────┬───────────┘
                                    │ JWT tokens
                                    ▼
┌──────────┐  POST /auth/*   ┌─────────────┐
│  Client   │───────────────▶│  Auth API   │  (public, no authorizer)
│  (curl /  │                │  Lambda      │
│  app)     │                └─────────────┘
│           │
│           │  GET|POST|DEL  ┌─────────────┐  validate   ┌────────────────┐
│           │──/events/*────▶│ API Gateway │────token───▶│ Lambda         │
│           │                │             │◀──policy────│ Authorizer     │
└──────────┘                └──────┬──────┘             │  ├ JWT verify   │
                                   │                     │  ├ JWKS cache   │
                                   │ proxy               │  └ DynamoDB     │
                                   ▼                     │    route lookup │
                            ┌─────────────┐             └───────┬────────┘
                            │ Events API  │                     │
                            │  Lambda     │                     ▼
                            │  ├ CRUD     │           ┌─────────────────┐
                            │  └ publish  │           │ Routes & Scopes │
                            └──────┬──────┘           │ DynamoDB Table  │
                                   │                  └─────────────────┘
                          ┌────────┴────────┐
                          ▼                 ▼
                   ┌────────────┐   ┌──────────────┐
                   │ Events     │   │ EventBridge  │
                   │ DynamoDB   │   │ Custom Bus   │
                   └────────────┘   └──────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| **Cognito User Pool** | Existing pool with groups `admins`, `deployers`, `viewers` |
| **API Gateway** | REST API with TOKEN-type Lambda Authorizer (300 s cache) |
| **Lambda Authorizer** | Validates JWT, queries DynamoDB routes, returns IAM policy |
| **Auth API Lambda** | Public `/auth/authorize` and `/auth/refresh` endpoints |
| **Events API Lambda** | Protected CRUD for events with visibility filtering |
| **Routes & Scopes Table** | DynamoDB table mapping route+method → allowed groups |
| **Events Table** | DynamoDB table for event records (GSI on visibility+createdAt) |
| **EventBridge Bus** | Custom bus for async event notifications |

---

## Prerequisites

- **AWS CLI** v2 – [Install](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **AWS SAM CLI** ≥ 1.100 – [Install](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- **Python** 3.11 – [Download](https://www.python.org/downloads/)
- **Docker** (required for `sam build --use-container`) – [Install](https://docs.docker.com/get-docker/)
- **AWS credentials** configured (`aws configure` or env vars)

---

## Quick Start

```bash
# 1. Build
cd cognito
sam build

# 2. Deploy (first time – guided)
sam deploy --guided

# 3. Seed the routes table with permission rules
pip install boto3
python scripts/seed_dynamodb.py

# 4. Test
python scripts/test_api.py \
  --api-url https://<api-id>.execute-api.us-east-1.amazonaws.com/dev \
  --username your-user@example.com \
  --password 'YourPassword!'
```

---

## Configuration

### Cognito Parameters

The template accepts these parameters (defaults match the existing pool):

- `CognitoUserPoolId` – default `us-east-1_Ibp76ZpqU`
- `CognitoClientId` – default `1tjaebcijmiaueqq6gp6drbkci`
- `CognitoRegion` – default `us-east-1`
- `Environment` – default `dev` (also: `staging`, `prod`)

Override at deploy time:

```bash
sam deploy --parameter-overrides \
  CognitoUserPoolId=us-east-1_XXXXXX \
  CognitoClientId=abc123 \
  Environment=prod
```

Or edit `samconfig.toml` → `parameter_overrides`.

---

## Deployment

### Build

```bash
# Without Docker (requires Python 3.11 on PATH)
sam build

# With Docker (recommended – matches Lambda runtime exactly)
sam build --use-container
```

### Deploy

```bash
# First time (interactive)
sam deploy --guided

# Subsequent deploys (uses samconfig.toml)
sam deploy
```

### Seed the Routes Table

After the stack is deployed, populate the routes table:

```bash
python scripts/seed_dynamodb.py
# Or with a custom table name:
python scripts/seed_dynamodb.py --table cognito-auth-system-routes-scopes
```

Default rules:

```
GET    /events            → viewers, deployers, admins
POST   /events            → deployers, admins
GET    /events/{eventId}  → viewers, deployers, admins
DELETE /events/{eventId}  → admins
```

---

## Testing

### Local Testing with SAM

```bash
# Start local API (authorizer won't run locally –
# protected endpoints receive requests without authorization check)
sam local start-api

# Invoke a single function with a sample event
sam local invoke AuthApiFunction -e events/auth_request.json
sam local invoke EventsApiFunction -e events/get_events_request.json
```

> **Note:** `sam local start-api` does not execute the Lambda Authorizer.
> When testing locally, protected endpoints are called directly. Use the
> `events/get_events_request.json` sample (which includes an `authorizer`
> context block) for realistic local invoke testing.

### Deployed API – curl Examples

```bash
API=https://<api-id>.execute-api.us-east-1.amazonaws.com/dev

# 1. Login
curl -s -X POST "$API/auth/authorize" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@example.com","password":"P@ssw0rd!"}'

# Save the AccessToken
TOKEN=$(curl -s -X POST "$API/auth/authorize" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@example.com","password":"P@ssw0rd!"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['tokens']['AccessToken'])")

# 2. List events
curl -s "$API/events" -H "Authorization: Bearer $TOKEN"

# 3. Create event
curl -s -X POST "$API/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"v3.0 Release","description":"Production deploy","visibility":"public"}'

# 4. Get single event
curl -s "$API/events/<event-id>" -H "Authorization: Bearer $TOKEN"

# 5. Delete event (admins only)
curl -s -X DELETE "$API/events/<event-id>" -H "Authorization: Bearer $TOKEN"

# 6. Refresh tokens
curl -s -X POST "$API/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'

# 7. Test 401 – no token
curl -s "$API/events"
```

### Automated Test Script

```bash
pip install requests
python scripts/test_api.py \
  --api-url "$API" \
  --username alice@example.com \
  --password 'P@ssw0rd!'
```

---

## API Reference

### Public Endpoints (no authorization)

#### POST /auth/authorize

Authenticate with username and password.

**Request:**
```json
{
  "username": "alice@example.com",
  "password": "P@ssw0rd!"
}
```

**Response (200):**
```json
{
  "message": "Authentication successful",
  "tokens": {
    "AccessToken": "eyJ...",
    "IdToken": "eyJ...",
    "RefreshToken": "eyJ...",
    "ExpiresIn": 3600,
    "TokenType": "Bearer"
  }
}
```

#### POST /auth/refresh

Exchange a refresh token for new access/ID tokens.

**Request:**
```json
{
  "refresh_token": "eyJjdH..."
}
```

**Response (200):**
```json
{
  "message": "Token refresh successful",
  "tokens": {
    "AccessToken": "eyJ...",
    "IdToken": "eyJ...",
    "ExpiresIn": 3600,
    "TokenType": "Bearer"
  }
}
```

### Protected Endpoints (require `Authorization: Bearer <AccessToken>`)

#### GET /events

List events visible to the caller's group.

- **admins** → all events
- **deployers** → public + internal
- **viewers** → public only

**Response (200):**
```json
{
  "events": [ ... ],
  "count": 5
}
```

#### POST /events

Create an event. Requires `deployers` or `admins` group.

**Request:**
```json
{
  "title": "v3.0 Release",
  "description": "Production deployment",
  "visibility": "public"
}
```

`visibility` must be `public`, `internal`, or `private`.  
Only `admins` can create `private` events.

**Response (201):**
```json
{
  "message": "Event created successfully",
  "event": { "eventId": "...", "title": "...", ... }
}
```

#### GET /events/{eventId}

Get a single event (visibility rules apply).

#### DELETE /events/{eventId}

Delete an event. Requires `admins` group.

---

## Authorization Flow (detailed)

1. Client sends `Authorization: Bearer <AccessToken>` header.
2. API Gateway extracts the token and invokes the Lambda Authorizer.
3. The authorizer:
   - Fetches JWKS from Cognito (cached 6 hours).
   - Verifies the JWT signature (RS256), expiration, issuer, and `token_use=access`.
   - Extracts `cognito:groups` from the token claims.
   - Queries DynamoDB: `route=/events`, `method=GET` → `allowed_groups`.
   - Returns `Allow` if any user group is in `allowed_groups`, else `Deny`.
4. API Gateway caches the policy for 300 seconds (per token).
5. On `Allow`, the downstream Lambda receives user context in `event.requestContext.authorizer`.

---

## Project Structure

```
cognito/
├── template.yaml              # SAM template (all infrastructure)
├── samconfig.toml             # SAM deployment configuration
├── src/
│   ├── authorizer/
│   │   ├── handler.py         # Lambda entry-point
│   │   ├── jwt_validator.py   # JWKS fetch + JWT verification
│   │   ├── policy_builder.py  # IAM policy document builder
│   │   └── requirements.txt   # PyJWT, cryptography, requests
│   ├── auth_api/
│   │   ├── handler.py         # Login + refresh handlers
│   │   └── requirements.txt
│   └── events_api/
│       ├── handler.py         # CRUD + EventBridge publish
│       └── requirements.txt
├── scripts/
│   ├── seed_dynamodb.py       # Seed routes table
│   └── test_api.py            # E2E test script
├── events/                    # Sample events for sam local invoke
│   ├── auth_request.json
│   └── get_events_request.json
├── .env.example               # Environment variable reference
└── README.md
```

---

## Troubleshooting

### `sam build` fails with cryptography errors

The `cryptography` package includes native code. Build inside Docker:

```bash
sam build --use-container
```

### 401 Unauthorized on every request

- Verify the token is an **Access Token** (not an ID Token).
- Check the `Authorization` header format: `Bearer <token>` (note the space).
- Ensure the Cognito User Pool ID and region match the deployed stack parameters.
- Check CloudWatch logs for the authorizer Lambda (`/aws/lambda/<stack>-authorizer`).

### 403 Forbidden – user has valid token

- The user's Cognito group may not be in `allowed_groups` for the route.
- Run `python scripts/seed_dynamodb.py` to ensure the routes table is populated.
- Verify the user is in the correct Cognito group (AWS Console → Cognito → Users).

### Token expired

- Access tokens expire after 1 hour (default Cognito setting).
- Use `POST /auth/refresh` with the refresh token to obtain new tokens.

### `sam local start-api` – authorizer not invoked

This is expected. SAM local does not execute Lambda Authorizers.
Use `sam local invoke` with sample events that include an `authorizer` context
block (see `events/get_events_request.json`).

### DynamoDB table not found

Ensure the stack deployed successfully and the table names match:

```bash
aws dynamodb list-tables --region us-east-1
```

Default names: `cognito-auth-system-routes-scopes`, `cognito-auth-system-events`.

---

## Adding New Routes

1. **Add the API Gateway route** in `template.yaml` under the target Lambda's `Events`.
2. **Update the authorizer** `_normalize_path()` if the route has path parameters.
3. **Seed a new rule** by adding an entry to `ROUTE_RULES` in `scripts/seed_dynamodb.py` and re-running it.

---

## Cleanup

```bash
sam delete --stack-name cognito-auth-system --region us-east-1
```

This removes the API Gateway, Lambda functions, DynamoDB tables, EventBridge bus,
and CloudWatch log groups. The **existing Cognito User Pool is NOT affected**.
