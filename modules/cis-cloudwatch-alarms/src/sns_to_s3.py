"""Archive SNS notifications (CIS CloudWatch alarms) as JSON objects in S3.

Object key layout: <prefix>YYYY/MM/DD/<alarm-name>/<message-id>.json
"""

import json
import logging
import os
import re
from datetime import datetime, timezone

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")

_S3 = None


def _s3_client():
    """Create the S3 client lazily so unit tests never need boto3."""
    global _S3  # pylint: disable=global-statement
    if _S3 is None:
        import boto3  # pylint: disable=import-outside-toplevel

        _S3 = boto3.client("s3")
    return _S3


def _alarm_name(message):
    """Return the alarm name of a CloudWatch alarm payload, or 'unknown'."""
    try:
        payload = json.loads(message)
    except (TypeError, ValueError):
        return "unknown"
    if not isinstance(payload, dict):
        return "unknown"
    return _SAFE_CHARS.sub("_", str(payload.get("AlarmName", "unknown"))) or "unknown"


def build_object(record, prefix, now=None):
    """Build the (key, body) pair stored for one SNS record."""
    sns = record["Sns"]
    now = now or datetime.now(timezone.utc)
    message_id = _SAFE_CHARS.sub("_", sns.get("MessageId", "no-id"))
    key = f"{prefix}{now:%Y/%m/%d}/{_alarm_name(sns.get('Message'))}/{message_id}.json"
    body = {
        "archived_at": now.isoformat(),
        "topic_arn": sns.get("TopicArn"),
        "subject": sns.get("Subject"),
        "timestamp": sns.get("Timestamp"),
        "message": sns.get("Message"),
    }
    return key, json.dumps(body, sort_keys=True)


def handler(event, _context, s3_client=None):
    """Lambda entry point."""
    bucket = os.environ["ARCHIVE_BUCKET"]
    prefix = os.environ.get("ARCHIVE_PREFIX", "")
    client = s3_client or _s3_client()

    keys = []
    for record in event.get("Records", []):
        if "Sns" not in record:
            continue
        key, body = build_object(record, prefix)
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
        )
        keys.append(key)

    LOGGER.info("Archived %d alert(s) to s3://%s/%s", len(keys), bucket, prefix)
    return {"archived": keys}
