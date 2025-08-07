#!/usr/bin/env python3
import os
import aws_cdk as cdk
from stacks.guardduty_enrichment_stack import GuardDutyEnrichmentStack

app = cdk.App()

# Get environment configuration
environment = app.node.try_get_context("environment") or "dev"
account = os.environ.get("CDK_DEFAULT_ACCOUNT")
region = os.environ.get("CDK_DEFAULT_REGION")

# Create the stack
GuardDutyEnrichmentStack(
    app,
    f"GuardDutyEnrichment-{environment}",
    environment=environment,
    env=cdk.Environment(account=account, region=region),
)

app.synth()