#!/usr/bin/env python3
"""Seed the Routes & Scopes DynamoDB table with authorization rules.

Usage:
    python scripts/seed_dynamodb.py                          # uses default table name
    python scripts/seed_dynamodb.py --table my-routes-table  # custom table name
    python scripts/seed_dynamodb.py --region eu-west-1       # custom region

The script is idempotent – re-running it overwrites existing items.
"""

import argparse
import json
import sys

import boto3

# ---------------------------------------------------------------------------
# Default route permission rules
# ---------------------------------------------------------------------------
ROUTE_RULES: list[dict] = [
    {
        "route": "/events",
        "method": "GET",
        "allowed_groups": ["viewers", "deployers", "admins"],
        "description": "List all events (filtered by visibility per group)",
    },
    {
        "route": "/events",
        "method": "POST",
        "allowed_groups": ["deployers", "admins"],
        "description": "Create a new event",
    },
    {
        "route": "/events/{eventId}",
        "method": "GET",
        "allowed_groups": ["viewers", "deployers", "admins"],
        "description": "Get a single event by ID",
    },
    {
        "route": "/events/{eventId}",
        "method": "DELETE",
        "allowed_groups": ["admins"],
        "description": "Delete an event by ID",
    },
]


def seed_routes(table_name: str, region: str) -> None:
    """Write all route rules to DynamoDB.

    Args:
        table_name: Name of the Routes & Scopes DynamoDB table.
        region: AWS region where the table lives.
    """
    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(table_name)

    print(f"Seeding table '{table_name}' in {region} ...")

    for rule in ROUTE_RULES:
        table.put_item(Item=rule)
        print(f"  ✓ {rule['method']:6s} {rule['route']:<25s} → {rule['allowed_groups']}")

    print(f"\nDone – {len(ROUTE_RULES)} route rules written.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed DynamoDB routes table")
    parser.add_argument(
        "--table",
        default="cognito-auth-system-routes-scopes",
        help="DynamoDB table name (default: cognito-auth-system-routes-scopes)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    args = parser.parse_args()

    try:
        seed_routes(args.table, args.region)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
