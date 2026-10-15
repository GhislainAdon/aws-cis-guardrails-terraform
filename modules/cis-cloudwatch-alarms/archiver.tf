# -----------------------------------------------------------------------------
# Optional SNS -> S3 archiver. Every alert published on the topic is stored as
# a JSON object so that the audit trail of CIS alarms survives e-mail retention.
# -----------------------------------------------------------------------------
locals {
  archiver_enabled       = var.enable_sns_archiver
  archiver_function_name = "${var.name_prefix}-cis-alert-archiver"
}

data "archive_file" "archiver" {
  count = local.archiver_enabled ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/src/sns_to_s3.py"
  output_path = "${path.module}/.build/sns_to_s3.zip"
}

data "aws_iam_policy_document" "archiver_assume" {
  count = local.archiver_enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "archiver" {
  count = local.archiver_enabled ? 1 : 0

  name               = "${local.archiver_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.archiver_assume[0].json

  tags = var.tags
}

data "aws_iam_policy_document" "archiver" {
  count = local.archiver_enabled ? 1 : 0

  statement {
    sid       = "WriteArchivedAlerts"
    actions   = ["s3:PutObject"]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${coalesce(var.archive_bucket_name, "unset")}/${var.archive_prefix}*"]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.archiver[0].arn}:*"]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "archiver" {
  count = local.archiver_enabled ? 1 : 0

  name   = "archive-alerts-to-s3"
  role   = aws_iam_role.archiver[0].id
  policy = data.aws_iam_policy_document.archiver[0].json
}

resource "aws_cloudwatch_log_group" "archiver" {
  #checkov:skip=CKV_AWS_158:KMS encryption is opt-in through var.lambda_log_kms_key_arn.
  count = local.archiver_enabled ? 1 : 0

  name              = "/aws/lambda/${local.archiver_function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = var.lambda_log_kms_key_arn

  tags = var.tags
}

resource "aws_lambda_function" "archiver" {
  #checkov:skip=CKV_AWS_117:The function only calls public AWS APIs (S3); no VPC resources are reached.
  #checkov:skip=CKV_AWS_116:Invoked asynchronously by SNS, which already retries delivery; a DLQ adds no value for an archive copy.
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for this reference implementation.
  #checkov:skip=CKV_AWS_173:Environment variables only contain the bucket name and prefix (no secrets).
  count = local.archiver_enabled ? 1 : 0

  function_name    = local.archiver_function_name
  description      = "Archives CIS benchmark alerts published on SNS into S3."
  role             = aws_iam_role.archiver[0].arn
  runtime          = "python3.12"
  handler          = "sns_to_s3.handler"
  filename         = data.archive_file.archiver[0].output_path
  source_code_hash = data.archive_file.archiver[0].output_base64sha256
  timeout          = 30
  memory_size      = 128

  reserved_concurrent_executions = 5

  environment {
    variables = {
      ARCHIVE_BUCKET = coalesce(var.archive_bucket_name, "unset")
      ARCHIVE_PREFIX = var.archive_prefix
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = var.tags

  depends_on = [aws_iam_role_policy.archiver, aws_cloudwatch_log_group.archiver]

  lifecycle {
    precondition {
      condition     = var.archive_bucket_name != null
      error_message = "archive_bucket_name is required when enable_sns_archiver is true."
    }
    precondition {
      condition     = local.sns_topic_arn != null
      error_message = "The archiver needs an SNS topic: set create_sns_topic = true or existing_sns_topic_arn."
    }
  }
}

resource "aws_lambda_permission" "archiver_from_sns" {
  count = local.archiver_enabled ? 1 : 0

  statement_id  = "AllowInvokeFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.archiver[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = local.sns_topic_arn
}

resource "aws_sns_topic_subscription" "archiver" {
  count = local.archiver_enabled ? 1 : 0

  topic_arn = local.sns_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.archiver[0].arn

  depends_on = [aws_lambda_permission.archiver_from_sns]
}
