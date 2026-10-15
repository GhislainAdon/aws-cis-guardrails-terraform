# 3. Remediation - Lambda function and its least-privilege role.
data "archive_file" "remediation" {
  type        = "zip"
  source_file = "${path.module}/src/remediation.py"
  output_path = "${path.module}/.build/remediation.zip"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "remediation" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "remediation" {
  statement {
    sid       = "ReadNetworkAcls"
    actions   = ["ec2:DescribeNetworkAcls"]
    resources = ["*"] # Describe* actions do not support resource-level permissions.
  }

  statement {
    sid       = "FixNetworkAclEntries"
    actions   = ["ec2:DeleteNetworkAclEntry", "ec2:CreateNetworkAclEntry"]
    resources = ["arn:${local.partition}:ec2:*:${local.account_id}:network-acl/*"]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.remediation.arn}:*"]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediation" {
  name   = "nacl-admin-port-remediation"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation.json
}

resource "aws_cloudwatch_log_group" "remediation" {
  #checkov:skip=CKV_AWS_158:KMS encryption is opt-in through var.lambda_log_kms_key_arn.
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = var.lambda_log_kms_key_arn

  tags = var.tags
}

resource "aws_lambda_function" "remediation" {
  #checkov:skip=CKV_AWS_117:The function only calls public AWS APIs (EC2, SNS); it does not need VPC access.
  #checkov:skip=CKV_AWS_116:EventBridge retry_policy handles failed deliveries; the Config rule re-evaluates and re-emits on the next change.
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for this reference implementation.
  #checkov:skip=CKV_AWS_173:Environment variables hold no secrets (topic ARN, port list, dry-run flag).
  function_name    = local.function_name
  description      = "Removes or shadows NACL entries exposing admin ports to the internet (CIS)."
  role             = aws_iam_role.remediation.arn
  runtime          = "python3.12"
  handler          = "remediation.handler"
  filename         = data.archive_file.remediation.output_path
  source_code_hash = data.archive_file.remediation.output_base64sha256
  timeout          = 60
  memory_size      = 128

  reserved_concurrent_executions = 5

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.notifications.arn
      ADMIN_PORTS   = join(",", var.admin_ports)
      DRY_RUN       = tostring(var.dry_run)
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = var.tags

  depends_on = [aws_iam_role_policy.remediation, aws_cloudwatch_log_group.remediation]
}
