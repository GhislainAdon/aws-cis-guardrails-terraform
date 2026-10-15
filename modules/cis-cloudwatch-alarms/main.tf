data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_cloudwatch_log_group" "cloudtrail" {
  name = var.cloudtrail_log_group_name
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each = local.controls

  name           = each.value.filter_name
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.value.metric_name
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each = local.controls

  alarm_name        = each.value.alarm_name
  alarm_description = "[${each.value.severity}] CIS ${each.key} - ${each.value.title}"

  namespace           = var.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.this[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = var.alarm_period
  evaluation_periods  = var.alarm_evaluation_periods
  threshold           = var.alarm_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = var.enable_ok_actions ? [local.sns_topic_arn] : []

  tags = var.tags

  lifecycle {
    precondition {
      condition     = local.sns_topic_arn != null
      error_message = "Set create_sns_topic = true or provide existing_sns_topic_arn."
    }
  }
}
