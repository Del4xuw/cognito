/**
 * JWT Token Validator for AWS Cognito Access Tokens.
 *
 * Fetches the JSON Web Key Set (JWKS) from Cognito, caches public keys for
 * 6 hours, and verifies token signature, expiration, issuer, and token_use.
 */

import { createRemoteJWKSet, jwtVerify, JWTPayload, JWTVerifyGetKey } from "jose";

// ---------------------------------------------------------------------------
// Module-level JWKS cache (persists across invocations within a container)
// ---------------------------------------------------------------------------
let jwksClient: JWTVerifyGetKey | null = null;
let jwksCacheTimestamp = 0;
const JWKS_CACHE_TTL = 21_600; // 6 hours in seconds

export interface CognitoClaims extends JWTPayload {
  username?: string;
  sub?: string;
  token_use?: string;
  "cognito:groups"?: string[];
}

export class JWTValidator {
  private readonly issuer: string;
  private readonly jwksUrl: URL;

  constructor(userPoolId: string, region: string) {
    this.issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    this.jwksUrl = new URL(`${this.issuer}/.well-known/jwks.json`);
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  /**
   * Validate a JWT token and return its decoded claims.
   *
   * Checks:
   *   1. Signature against Cognito JWKS public key (RS256).
   *   2. `exp` – token must not be expired.
   *   3. `iss` – must match the expected Cognito User Pool issuer.
   *   4. `token_use` – must be "access".
   *
   * @param token - Raw JWT string (without the `Bearer` prefix).
   * @returns Decoded claims object on success, null on any failure.
   */
  async validateToken(token: string): Promise<CognitoClaims | null> {
    try {
      const jwks = this.getJwksClient();

      const { payload } = await jwtVerify(token, jwks, {
        issuer: this.issuer,
        algorithms: ["RS256"],
      });

      const claims = payload as CognitoClaims;

      // Ensure the token is an access token
      if (claims.token_use !== "access") {
        console.warn(
          `Unexpected token_use=${claims.token_use} (expected 'access')`
        );
        return null;
      }

      return claims;
    } catch (err) {
      const error = err as Error;

      if (error.message?.includes("expired")) {
        console.warn("Token has expired");
      } else if (error.message?.includes("issuer")) {
        console.warn("Token issuer mismatch");
      } else {
        console.warn("Invalid token:", error.message);
      }

      // If verification failed, try refreshing JWKS cache and retry once
      // (handles key rotation)
      try {
        this.invalidateCache();
        const jwks = this.getJwksClient();

        const { payload } = await jwtVerify(token, jwks, {
          issuer: this.issuer,
          algorithms: ["RS256"],
        });

        const claims = payload as CognitoClaims;

        if (claims.token_use !== "access") {
          console.warn(
            `Unexpected token_use=${claims.token_use} (expected 'access')`
          );
          return null;
        }

        return claims;
      } catch (retryErr) {
        console.error(
          JSON.stringify({
            message: "Token validation error after JWKS refresh",
            error: (retryErr as Error).message,
          })
        );
        return null;
      }
    }
  }

  // ------------------------------------------------------------------
  // Private helpers
  // ------------------------------------------------------------------

  /**
   * Return a JWKS client, creating or refreshing as needed based on TTL.
   * The `jose` library handles caching internally within the client instance,
   * but we control when to recreate the client to enforce our 6-hour TTL.
   */
  private getJwksClient(): JWTVerifyGetKey {
    const now = Date.now() / 1000;

    if (jwksClient && now - jwksCacheTimestamp < JWKS_CACHE_TTL) {
      return jwksClient;
    }

    jwksClient = createRemoteJWKSet(this.jwksUrl);
    jwksCacheTimestamp = Date.now() / 1000;

    console.info(
      JSON.stringify({ message: "JWKS client created/refreshed" })
    );

    return jwksClient;
  }

  /** Force the next getJwksClient() call to create a fresh client. */
  private invalidateCache(): void {
    jwksCacheTimestamp = 0;
    jwksClient = null;
  }
}
