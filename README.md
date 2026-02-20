# Cognito Auth System — Serverless Authorization (TypeScript)

Sistema de autorización serverless construido con **AWS SAM**, **TypeScript** y **Node.js 20.x**.
Utiliza Cognito User Pool, API Gateway con Lambda Token Authorizer, DynamoDB y EventBridge.

---

## Arquitectura

```
                         ┌──────────────┐
                         │   Cognito    │
                         │  User Pool   │
                         └──────┬───────┘
                                │ JWT (Access Token)
                                ▼
┌───────────┐  Authorization  ┌──────────────────┐  Allow/Deny  ┌───────────────┐
│  Cliente  │ ──────────────► │   API Gateway    │ ◄─────────── │  Authorizer   │
│  (curl)   │                 │  (REST API)      │              │  Lambda       │
└───────────┘                 └──────┬───────────┘              │  ┌─────────┐  │
                                     │                          │  │  JWKS   │  │
                              ┌──────┴──────┐                   │  │ (cache  │  │
                              │             │                   │  │ 6 hrs)  │  │
                         ┌────▼───┐   ┌─────▼────┐             │  └─────────┘  │
                         │ Auth   │   │ Events   │             └───────┬───────┘
                         │ API    │   │ API      │                     │
                         └────────┘   └─────┬────┘              ┌─────▼──────┐
                                            │                   │ DynamoDB   │
                                     ┌──────┴──────┐           │ routes-    │
                                     │             │           │ scopes     │
                               ┌─────▼────┐  ┌────▼──────┐    └────────────┘
                               │ DynamoDB │  │EventBridge│
                               │ events   │  │ (bus)     │
                               └──────────┘  └───────────┘
```

---

## Estructura del Proyecto

```
cognito/
├── template.yaml              # SAM template (Node.js 20.x + esbuild)
├── samconfig.toml             # Configuración de despliegue SAM
├── README.md
├── src/
│   ├── authorizer/            # Lambda Token Authorizer
│   │   ├── handler.ts         # Entry point — extrae token, valida JWT, consulta DynamoDB
│   │   ├── jwtValidator.ts    # Validación JWT con jose (JWKS cache 6h)
│   │   ├── policyBuilder.ts   # Genera IAM policy (Allow/Deny)
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── auth_api/              # Endpoints públicos de autenticación
│   │   ├── handler.ts         # POST /auth/authorize y POST /auth/refresh
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── events_api/            # CRUD protegido de eventos
│       ├── handler.ts         # GET/POST /events, GET/DELETE /events/{eventId}
│       ├── package.json
│       └── tsconfig.json
├── scripts/
│   ├── seed_dynamodb.ts       # Seed de reglas de rutas en DynamoDB
│   ├── test_api.ts            # Tests end-to-end contra la API desplegada
│   ├── package.json
│   └── tsconfig.json
└── events/
    ├── auth_request.json      # Evento de prueba para sam local invoke (Auth API)
    └── get_events_request.json # Evento de prueba para sam local invoke (Events API)
```

---

## Stack Tecnológico

| Componente | Tecnología |
|---|---|
| Runtime | Node.js 20.x |
| Lenguaje | TypeScript 5.x |
| Bundler | esbuild (via SAM) |
| IaC | AWS SAM (CloudFormation) |
| JWT | `jose` (JWKS + RS256) |
| AWS SDK | v3 (`@aws-sdk/client-*`, `@aws-sdk/lib-dynamodb`) |
| Auth | AWS Cognito User Pool |
| API | API Gateway REST (Lambda Proxy) |
| DB | DynamoDB (PAY_PER_REQUEST) |
| Eventos | EventBridge (custom bus) |
| Logs | CloudWatch (retención 7 días) |

---

## Prerrequisitos

- **Node.js 20.x** — [https://nodejs.org](https://nodejs.org)
- **AWS SAM CLI** — [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- **AWS CLI** configurado con credenciales (`aws configure`)
- **Docker** (requerido para `sam build --use-container`)
- Un **Cognito User Pool** existente con:
  - App Client con `USER_PASSWORD_AUTH` habilitado
  - Grupos creados: `admins`, `deployers`, `viewers`
  - Al menos un usuario asignado a un grupo

---

## 1. Instalación de Dependencias

```powershell
# Instalar dependencias de cada Lambda
npm install --prefix src/authorizer
npm install --prefix src/auth_api
npm install --prefix src/events_api

# Instalar dependencias de los scripts
npm install --prefix scripts
```

---

## 2. Build

```powershell
sam build
```

SAM usa **esbuild** para compilar TypeScript, minificar y generar sourcemaps. Los paquetes `@aws-sdk/*` se marcan como `External` porque ya vienen incluidos en el runtime de Node.js 20.x de Lambda.

---

## 3. Despliegue

### Primera vez (configuración guiada)

```powershell
sam deploy --guided
```

Se te pedirá confirmar los parámetros:

| Parámetro | Valor por defecto |
|---|---|
| Stack name | `cognito-auth-system` |
| CognitoUserPoolId | `us-east-1_Ibp76ZpqU` |
| CognitoClientId | `5g48nkghk7pvbdu8joaa2kvdi8` |
| CognitoRegion | `us-east-1` |
| Environment | `dev` |

### Despliegues posteriores

```powershell
sam deploy
```

Los valores se guardan en `samconfig.toml`.

### Obtener la URL de la API

```powershell
aws cloudformation describe-stacks --stack-name cognito-auth-system --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text
```

Guárdala para los pasos siguientes:

```powershell
$API_URL = "https://<api-id>.execute-api.us-east-1.amazonaws.com/dev"
```

---

## 4. Seed de Permisos (DynamoDB)

El script `seed_dynamodb.ts` carga las reglas de autorización por ruta en la tabla `routes-scopes`:

```powershell
npx ts-node scripts/seed_dynamodb.ts
```

Con parámetros opcionales:

```powershell
npx ts-node scripts/seed_dynamodb.ts --table cognito-auth-system-routes-scopes --region us-east-1
```

### Reglas configuradas

| Ruta | Método | Grupos permitidos |
|---|---|---|
| `/events` | GET | viewers, deployers, admins |
| `/events` | POST | deployers, admins |
| `/events/{eventId}` | GET | viewers, deployers, admins |
| `/events/{eventId}` | DELETE | admins |

---

## 5. Demo — Flujo Completo

### 5.1 Login (obtener tokens)

```powershell
curl -X POST "$API_URL/auth/authorize" `
  -H "Content-Type: application/json" `
  -d '{"username": "admin@example.com", "password": "YourPassword123!"}'
```

Respuesta exitosa (HTTP 200):

```json
{
  "message": "Authentication successful",
  "tokens": {
    "AccessToken": "eyJraWQ...",
    "IdToken": "eyJraWQ...",
    "RefreshToken": "eyJjdH...",
    "ExpiresIn": 3600,
    "TokenType": "Bearer"
  }
}
```

Guarda el token:

```powershell
$TOKEN = "eyJraWQ..."
```

### 5.2 Refresh Token

```powershell
curl -X POST "$API_URL/auth/refresh" `
  -H "Content-Type: application/json" `
  -d '{"refresh_token": "eyJjdH..."}'
```

### 5.3 Listar eventos (GET /events)

```powershell
curl -X GET "$API_URL/events" `
  -H "Authorization: Bearer $TOKEN"
```

La respuesta varía según el grupo del usuario:
- **admins** — ve todos los eventos (public, internal, private)
- **deployers** — ve public + internal
- **viewers** — ve solo public

### 5.4 Crear evento (POST /events)

```powershell
curl -X POST "$API_URL/events" `
  -H "Authorization: Bearer $TOKEN" `
  -H "Content-Type: application/json" `
  -d '{"title": "Deploy v2.1", "description": "Release to production", "visibility": "public"}'
```

Respuesta (HTTP 201):

```json
{
  "message": "Event created successfully",
  "event": {
    "eventId": "a1b2c3d4-...",
    "title": "Deploy v2.1",
    "description": "Release to production",
    "visibility": "public",
    "createdBy": "admin@example.com",
    "createdAt": 1740024000
  }
}
```

Valores de `visibility`: `public`, `internal`, `private` (solo admins pueden crear `private`).

### 5.5 Obtener evento por ID (GET /events/{eventId})

```powershell
curl -X GET "$API_URL/events/a1b2c3d4-..." `
  -H "Authorization: Bearer $TOKEN"
```

### 5.6 Eliminar evento (DELETE /events/{eventId})

Solo usuarios del grupo **admins**:

```powershell
curl -X DELETE "$API_URL/events/a1b2c3d4-..." `
  -H "Authorization: Bearer $TOKEN"
```

### 5.7 Pruebas de autorización fallida

**Sin token** (esperado: HTTP 401):

```powershell
curl -X GET "$API_URL/events"
```

**Token inválido** (esperado: HTTP 401/403):

```powershell
curl -X GET "$API_URL/events" `
  -H "Authorization: Bearer invalid.token.here"
```

**Viewer intentando crear** (esperado: HTTP 403 del authorizer):

```powershell
# Autenticarse como un usuario del grupo "viewers"
curl -X POST "$API_URL/events" `
  -H "Authorization: Bearer $VIEWER_TOKEN" `
  -H "Content-Type: application/json" `
  -d '{"title": "Test", "visibility": "public"}'
```

---

## 6. Tests End-to-End Automatizados

```powershell
npx ts-node scripts/test_api.ts `
  --api-url $API_URL `
  --username admin@example.com `
  --password "YourPassword123!"
```

El script ejecuta secuencialmente:
1. Login (`POST /auth/authorize`)
2. Refresh token (`POST /auth/refresh`)
3. Listar eventos (`GET /events`)
4. Crear evento (`POST /events`)
5. Obtener evento (`GET /events/{eventId}`)
6. Eliminar evento (`DELETE /events/{eventId}`)
7. Acceso sin token (espera 401)
8. Token inválido (espera 401/403)

---

## 7. Pruebas Locales con SAM

### Invocar funciones individualmente

```powershell
# Auth API — login
sam local invoke AuthApiFunction -e events/auth_request.json

# Events API — listar eventos
sam local invoke EventsApiFunction -e events/get_events_request.json
```

### Levantar API local completa

```powershell
sam local start-api --warm-containers EAGER
```

Luego usar `http://127.0.0.1:3000` como `$API_URL`.

> **Nota:** El Authorizer Lambda necesita conectividad a Cognito (JWKS) y DynamoDB.
> Para pruebas locales, asegúrate de tener credenciales AWS configuradas.

---

## 8. Verificar en CloudWatch

Después del despliegue, revisa los logs de cada función:

```powershell
# Logs del Authorizer
aws logs tail /aws/lambda/cognito-auth-system-authorizer --follow

# Logs del Auth API
aws logs tail /aws/lambda/cognito-auth-system-auth-api --follow

# Logs del Events API
aws logs tail /aws/lambda/cognito-auth-system-events-api --follow
```

Busca mensajes clave:
- `"JWKS client created/refreshed"` — confirmación de cache JWKS
- `"Token validated"` — JWT validado exitosamente
- `"Authorization decision"` — Allow/Deny con ruta y grupos
- `"EventBridge publish OK"` — evento publicado correctamente

---

## 9. Limpieza

```powershell
# Eliminar el stack completo
sam delete --stack-name cognito-auth-system

# O con confirmación automática
sam delete --stack-name cognito-auth-system --no-prompts
```

Esto elimina: Lambdas, API Gateway, DynamoDB tables, EventBridge bus y CloudWatch Log Groups.

---

## Flujo de Autorización (detalle)

```
1. Cliente envía: Authorization: Bearer <JWT>
2. API Gateway extrae el header y llama al Authorizer Lambda
3. Authorizer Lambda:
   a. Extrae el token (soporta "Bearer <token>" y token directo)
   b. Valida JWT contra JWKS de Cognito (RS256, cache 6h en memoria)
      - Verifica firma, expiración, issuer, token_use="access"
      - Si falla por kid desconocido, refresca JWKS y reintenta
   c. Extrae username y cognito:groups del token
   d. Normaliza la ruta (/events/abc-123 → /events/{eventId})
   e. Consulta DynamoDB (routes-scopes): ¿algún grupo del usuario está en allowed_groups?
   f. Retorna IAM policy: Allow o Deny con wildcard resource (stage/*/*)
   g. Incluye context: username, groups, sub → disponible en requestContext.authorizer
4. API Gateway cachea la policy por 300 segundos (ReauthorizeEvery)
5. Si Allow → ejecuta la Lambda destino (Auth API o Events API)
6. Si Deny → retorna 403 Forbidden
```

---

## Variables de Entorno

### Todas las Lambdas (via Globals)
- `COGNITO_USER_POOL_ID` — ID del User Pool
- `COGNITO_CLIENT_ID` — App Client ID
- `COGNITO_REGION` — Región del User Pool
- `ENVIRONMENT` — dev / staging / prod

### Authorizer Lambda
- `ROUTES_SCOPES_TABLE` — Nombre de la tabla DynamoDB de permisos

### Events API Lambda
- `EVENTS_TABLE` — Nombre de la tabla DynamoDB de eventos
- `EVENTBRIDGE_BUS_NAME` — Nombre del bus de EventBridge
