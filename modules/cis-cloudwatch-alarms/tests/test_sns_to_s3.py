"""Unit tests for the SNS -> S3 archiver (no AWS access, no boto3 needed)."""

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import sns_to_s3  # noqa: E402  pylint: disable=wrong-import-position


def _record(message, message_id="abc-123"):
    return {
        "Sns": {
            "MessageId": message_id,
            "TopicArn": "arn:aws:sns:eu-west-3:123456789012:cis-benchmark-alerts",
            "Subject": "ALARM",
            "Timestamp": "2025-09-01T10:00:00.000Z",
            "Message": message,
        }
    }


class BuildObjectTest(unittest.TestCase):
    NOW = datetime(2025, 9, 1, 10, 0, tzinfo=timezone.utc)

    def test_key_uses_date_alarm_and_message_id(self):
        message = json.dumps({"AlarmName": "lz-CIS-4.3-RootAccountUsage"})
        key, body = sns_to_s3.build_object(_record(message), "cis-alerts/", self.NOW)
        self.assertEqual(key, "cis-alerts/2025/09/01/lz-CIS-4.3-RootAccountUsage/abc-123.json")
        self.assertEqual(json.loads(body)["message"], message)

    def test_non_json_message_falls_back_to_unknown(self):
        key, _ = sns_to_s3.build_object(_record("plain text"), "", self.NOW)
        self.assertIn("/unknown/", key)

    def test_slashes_cannot_escape_the_key_layout(self):
        message = json.dumps({"AlarmName": "../../etc passwd"})
        key, _ = sns_to_s3.build_object(_record(message, "id/../x"), "p/", self.NOW)
        self.assertEqual(key, "p/2025/09/01/.._.._etc_passwd/id_.._x.json")


class HandlerTest(unittest.TestCase):
    @mock.patch.dict(os.environ, {"ARCHIVE_BUCKET": "example-archive", "ARCHIVE_PREFIX": "cis/"})
    def test_puts_one_object_per_sns_record(self):
        s3 = mock.Mock()
        event = {"Records": [_record("{}", "1"), _record("{}", "2"), {"EventSource": "other"}]}
        result = sns_to_s3.handler(event, None, s3_client=s3)
        self.assertEqual(len(result["archived"]), 2)
        self.assertEqual(s3.put_object.call_count, 2)
        kwargs = s3.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], "example-archive")
        self.assertEqual(kwargs["ContentType"], "application/json")


if __name__ == "__main__":
    unittest.main()
