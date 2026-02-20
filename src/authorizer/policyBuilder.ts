/**
 * IAM Policy Builder for API Gateway Lambda Authorizer responses.
 */

import { APIGatewayAuthorizerResult, StatementEffect } from "aws-lambda";

export interface PolicyContext {
  [key: string]: string | number | boolean;
}

export class PolicyBuilder {
  /**
   * Create a complete authorizer response.
   *
   * @param principalId - Unique identifier for the caller (typically `sub`).
   * @param effect - "Allow" or "Deny".
   * @param resource - The `methodArn` from the authorizer event.
   * @param context - Key/value pairs forwarded to the downstream Lambda via
   *                  `event.requestContext.authorizer`. Values must be
   *                  strings, numbers, or booleans (API Gateway limitation).
   * @returns Authorizer response with principalId, policyDocument, and optional context.
   */
  static build(
    principalId: string,
    effect: StatementEffect,
    resource: string,
    context?: Record<string, unknown>
  ): APIGatewayAuthorizerResult {
    // Extract base ARN and apply wildcard to allow all methods/resources
    // Format: arn:aws:execute-api:region:account:api-id/stage/method/resource
    // We want: arn:aws:execute-api:region:account:api-id/stage/*/*
    const resourceParts = resource.split("/");
    let wildcardResource: string;

    if (resourceParts.length >= 2) {
      wildcardResource = `${resourceParts[0]}/${resourceParts[1]}/*/*`;
      console.info(`Original resource: ${resource}`);
      console.info(`Wildcard resource: ${wildcardResource}`);
    } else {
      wildcardResource = resource;
      console.warn(
        `Unable to parse resource ARN, using exact match: ${resource}`
      );
    }

    const policy: APIGatewayAuthorizerResult = {
      principalId,
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: effect,
            Resource: wildcardResource,
          },
        ],
      },
    };

    if (context) {
      const sanitized: PolicyContext = {};
      for (const [key, value] of Object.entries(context)) {
        if (
          typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "boolean"
        ) {
          sanitized[key] = value;
        } else {
          sanitized[key] = String(value);
        }
      }
      policy.context = sanitized;
    }

    console.info(
      `Generated policy for principal ${principalId}: ${effect} on ${wildcardResource}`
    );
    return policy;
  }
}
