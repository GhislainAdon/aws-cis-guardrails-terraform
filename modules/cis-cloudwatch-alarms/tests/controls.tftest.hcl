# Offline plan tests (terraform >= 1.7): the AWS provider is mocked, so no
# credentials or network access are needed.
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_cloudwatch_log_group" {
    defaults = {
      name = "aws-controltower/CloudTrailLogs"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:eu-west-3:123456789012:cis-benchmark-alerts"
    }
  }
}

mock_provider "archive" {}

variables {
  cloudtrail_log_group_name = "aws-controltower/CloudTrailLogs"
  alert_email_endpoints     = ["security@example.com"]
}

run "deploys_all_fifteen_controls_by_default" {
  command = plan

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 15 && length(aws_cloudwatch_metric_alarm.this) == 15
    error_message = "Expected 15 metric filters and 15 alarms."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["4.7"].pattern == "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    error_message = "Generated pattern for 4.7 is not the expected one."
  }

  assert {
    condition     = alltrue([for f in aws_cloudwatch_log_metric_filter.this : f.metric_transformation[0].namespace == "CISBenchmark"])
    error_message = "All metrics must be published in the CISBenchmark namespace."
  }
}

run "deploys_only_selected_controls" {
  command = plan

  variables {
    enabled_controls = ["4.1", "4.3"]
  }

  assert {
    condition     = toset(keys(aws_cloudwatch_metric_alarm.this)) == toset(["4.1", "4.3"])
    error_message = "Only the selected controls must be deployed."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.this["4.3"].alarm_name == "lz-CIS-4.3-RootAccountUsage"
    error_message = "Unexpected alarm naming convention."
  }
}

run "rejects_unknown_control" {
  command = plan

  variables {
    enabled_controls = ["4.16"]
  }

  expect_failures = [var.enabled_controls]
}

run "rejects_tags_outside_the_tag_policy" {
  command = plan

  variables {
    tags = {
      Project = "forbidden"
    }
  }

  expect_failures = [var.tags]
}

run "requires_a_topic" {
  command = plan

  variables {
    create_sns_topic = false
  }

  expect_failures = [aws_cloudwatch_metric_alarm.this]
}
