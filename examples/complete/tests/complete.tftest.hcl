# Offline plan of the whole example with mocked providers (terraform >= 1.7).
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

  mock_data "aws_region" {
    defaults = {
      region = "eu-west-3"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:eu-west-3:123456789012:example-topic"
    }
  }

  mock_resource "aws_lambda_function" {
    defaults = {
      arn = "arn:aws:lambda:eu-west-3:123456789012:function:example"
    }
  }

  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn = "arn:aws:events:eu-west-3:123456789012:rule/example"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-west-3:123456789012:log-group:example"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/example"
    }
  }
}

mock_provider "archive" {}

run "plans_every_guardrail" {
  command = plan

  assert {
    condition     = length(module.cis_alarms.enabled_controls) == 15
    error_message = "All 15 CIS 4.x controls should be planned."
  }

  assert {
    condition     = module.security_hub.standards_arns["cis-aws-foundations-benchmark/v/3.0.0"] == "arn:aws:securityhub:eu-west-3::standards/cis-aws-foundations-benchmark/v/3.0.0"
    error_message = "Unexpected Security Hub standard ARN."
  }
}

run "support_role_rejects_wildcard_principals" {
  command = plan

  module {
    source = "../../modules/support-role"
  }

  variables {
    trusted_principal_arns = ["arn:aws:iam::123456789012:role/*"]
  }

  expect_failures = [var.trusted_principal_arns]
}
