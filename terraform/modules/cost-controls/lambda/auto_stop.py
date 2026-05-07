"""
auto_stop.py

Stops every running EC2 instance tagged Project=<project> in the current
region. Runs nightly via EventBridge. Reports the result to SNS.

This is "Layer 2" of the cost-controls model:
  Layer 1 — AWS Budgets alert at 80%/100% of monthly threshold
  Layer 2 — this nightly auto-stop (proactive, scheduled)
  Layer 3 — GitHub Actions cost-runaway check (independent observer)

If all three layers fail simultaneously, you owe AWS money. Defense in depth.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import boto3

PROJECT_TAG = os.environ["PROJECT_TAG"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def lambda_handler(event, context):
    """Entry point. event/context are unused; we always operate on tagged instances."""
    ec2 = boto3.client("ec2")
    sns = boto3.client("sns")

    # Find all running instances with the project tag
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Project", "Values": [PROJECT_TAG]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )

    running = []
    for reservation in response["Reservations"]:
        for inst in reservation["Instances"]:
            name_tag = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                "(unnamed)",
            )
            running.append((inst["InstanceId"], name_tag, inst["InstanceType"]))

    timestamp = datetime.now(timezone.utc).isoformat()

    if not running:
        message = f"[{timestamp}] No running instances tagged Project={PROJECT_TAG}. Nothing to stop."
        print(message)
        # Don't notify on the no-op case — would create inbox noise every night
        return {"stopped": [], "timestamp": timestamp}

    instance_ids = [i[0] for i in running]
    print(f"[{timestamp}] Stopping {len(instance_ids)} instances: {instance_ids}")

    ec2.stop_instances(InstanceIds=instance_ids)

    # Build a human-readable SNS notification
    lines = [
        f"Lab auto-stop fired at {timestamp}",
        f"Project: {PROJECT_TAG}",
        f"Stopped {len(running)} instance(s):",
        "",
    ]
    for iid, name, itype in running:
        lines.append(f"  - {name} ({iid}, {itype})")
    lines += [
        "",
        "If this was unexpected, check the EventBridge schedule and your terraform.tfvars.",
        "To restart: aws ec2 start-instances --instance-ids " + " ".join(instance_ids),
    ]
    body = "\n".join(lines)

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[lab] Auto-stop: {len(running)} instance(s) stopped",
        Message=body,
    )

    return {
        "stopped": [
            {"instance_id": iid, "name": name, "type": itype}
            for iid, name, itype in running
        ],
        "timestamp": timestamp,
    }
