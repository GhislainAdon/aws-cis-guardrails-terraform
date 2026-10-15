# -----------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - section 4 (Monitoring) as data.
#
# Each control is described once. A control either provides a raw CloudWatch
# Logs filter `pattern`, or an optional `event_source` plus a list of
# `event_names` from which the pattern is generated. Adding a control means
# adding one entry here; no new resource, module or output is needed.
# -----------------------------------------------------------------------------
locals {
  cis_controls = {
    "4.1" = {
      slug         = "UnauthorizedAPICalls"
      title        = "Unauthorized API calls"
      severity     = "MEDIUM"
      event_source = null
      event_names  = []
      pattern      = "{ (($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")) && ($.sourceIPAddress != \"delivery.logs.amazonaws.com\") && ($.eventName != \"HeadBucket\") }"
    }
    "4.2" = {
      slug         = "ConsoleSignInWithoutMFA"
      title        = "Management console sign-in without MFA"
      severity     = "HIGH"
      event_source = null
      event_names  = []
      pattern      = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    "4.3" = {
      slug         = "RootAccountUsage"
      title        = "Usage of the root account"
      severity     = "CRITICAL"
      event_source = null
      event_names  = []
      pattern      = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    "4.4" = {
      slug         = "IAMPolicyChanges"
      title        = "IAM policy changes"
      severity     = "HIGH"
      event_source = null
      event_names = [
        "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy",
        "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy",
        "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
        "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
        "AttachGroupPolicy", "DetachGroupPolicy",
      ]
      pattern = null
    }
    "4.5" = {
      slug         = "CloudTrailConfigChanges"
      title        = "CloudTrail configuration changes"
      severity     = "CRITICAL"
      event_source = null
      event_names  = ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"]
      pattern      = null
    }
    "4.6" = {
      slug         = "ConsoleAuthenticationFailures"
      title        = "Management console authentication failures"
      severity     = "MEDIUM"
      event_source = null
      event_names  = []
      pattern      = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    "4.7" = {
      slug         = "CMKDisableOrScheduledDeletion"
      title        = "Disabling or scheduled deletion of customer managed keys"
      severity     = "HIGH"
      event_source = "kms.amazonaws.com"
      event_names  = ["DisableKey", "ScheduleKeyDeletion"]
      pattern      = null
    }
    "4.8" = {
      slug         = "S3BucketPolicyChanges"
      title        = "S3 bucket policy changes"
      severity     = "HIGH"
      event_source = "s3.amazonaws.com"
      event_names = [
        "PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "PutBucketReplication",
        "DeleteBucketPolicy", "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication",
      ]
      pattern = null
    }
    "4.9" = {
      slug         = "AWSConfigChanges"
      title        = "AWS Config configuration changes"
      severity     = "HIGH"
      event_source = "config.amazonaws.com"
      event_names  = ["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"]
      pattern      = null
    }
    "4.10" = {
      slug         = "SecurityGroupChanges"
      title        = "Security group changes"
      severity     = "MEDIUM"
      event_source = null
      event_names = [
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
        "CreateSecurityGroup", "DeleteSecurityGroup",
      ]
      pattern = null
    }
    "4.11" = {
      slug         = "NACLChanges"
      title        = "Network ACL changes"
      severity     = "MEDIUM"
      event_source = null
      event_names = [
        "CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry",
        "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation",
      ]
      pattern = null
    }
    "4.12" = {
      slug         = "NetworkGatewayChanges"
      title        = "Network gateway changes"
      severity     = "MEDIUM"
      event_source = null
      event_names = [
        "CreateCustomerGateway", "DeleteCustomerGateway",
        "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway",
      ]
      pattern = null
    }
    "4.13" = {
      slug         = "RouteTableChanges"
      title        = "Route table changes"
      severity     = "MEDIUM"
      event_source = "ec2.amazonaws.com"
      event_names = [
        "CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation",
        "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable",
      ]
      pattern = null
    }
    "4.14" = {
      slug         = "VPCChanges"
      title        = "VPC changes"
      severity     = "MEDIUM"
      event_source = null
      event_names = [
        "CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
        "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection",
        "AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink", "EnableVpcClassicLink",
      ]
      pattern = null
    }
    "4.15" = {
      slug         = "OrganizationsChanges"
      title        = "AWS Organizations changes"
      severity     = "HIGH"
      event_source = "organizations.amazonaws.com"
      event_names = [
        "AcceptHandshake", "AttachPolicy", "CreateAccount", "CreateOrganizationalUnit", "CreatePolicy",
        "DeclineHandshake", "DeleteOrganization", "DeleteOrganizationalUnit", "DeletePolicy", "DetachPolicy",
        "DisablePolicyType", "EnablePolicyType", "InviteAccountToOrganization", "LeaveOrganization",
        "MoveAccount", "RemoveAccountFromOrganization", "UpdatePolicy", "UpdateOrganizationalUnit",
      ]
      pattern = null
    }
  }

  # Controls selected by the caller (null = all of them).
  selected_control_ids = var.enabled_controls == null ? keys(local.cis_controls) : var.enabled_controls

  # Final, fully-resolved data model consumed by every resource of the module.
  controls = {
    for id in local.selected_control_ids : id => {
      title       = local.cis_controls[id].title
      severity    = local.cis_controls[id].severity
      filter_name = "${var.name_prefix}-CIS-${id}-${local.cis_controls[id].slug}"
      alarm_name  = "${var.name_prefix}-CIS-${id}-${local.cis_controls[id].slug}"
      metric_name = "CIS-${id}-${local.cis_controls[id].slug}"
      pattern = local.cis_controls[id].pattern != null ? local.cis_controls[id].pattern : (
        local.cis_controls[id].event_source == null
        ? "{ ${join(" || ", [for e in local.cis_controls[id].event_names : "($.eventName = ${e})"])} }"
        : "{ ($.eventSource = ${local.cis_controls[id].event_source}) && (${join(" || ", [for e in local.cis_controls[id].event_names : "($.eventName = ${e})"])}) }"
      )
    }
  }

  sns_topic_arn = var.create_sns_topic ? aws_sns_topic.alerts[0].arn : var.existing_sns_topic_arn
}
