data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  export_regions = toset(var.guardduty_export_regions)

  normalized_destination_prefix = var.guardduty_export_destination_prefix == null ? "" : trimsuffix(trimprefix(var.guardduty_export_destination_prefix, "/"), "/")
  destination_arn               = local.normalized_destination_prefix == "" ? var.guardduty_findings_bucket_arn : "${var.guardduty_findings_bucket_arn}/${local.normalized_destination_prefix}"
  destination_object_arn        = local.normalized_destination_prefix == "" ? "${var.guardduty_findings_bucket_arn}/*" : "${var.guardduty_findings_bucket_arn}/${local.normalized_destination_prefix}/*"
  guardduty_detector_arn        = "arn:${data.aws_partition.current.partition}:guardduty:*:${data.aws_caller_identity.current.account_id}:detector/*"

}

data "aws_guardduty_detector" "existing" {
  for_each = local.export_regions

  region = each.key
}

data "aws_iam_policy_document" "guardduty_export_bucket" {
  statement {
    sid     = "AllowGuardDutyGetBucketLocation"
    effect  = "Allow"
    actions = ["s3:GetBucketLocation"]

    resources = [var.guardduty_findings_bucket_arn]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.guardduty_detector_arn]
    }
  }

  statement {
    sid     = "AllowGuardDutyPutFindings"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    resources = [local.destination_object_arn]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.guardduty_detector_arn]
    }
  }
}

data "aws_iam_policy_document" "guardduty_export_kms" {
  statement {
    sid     = "AllowGuardDutyGenerateDataKey"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey"]

    resources = [var.guardduty_findings_kms_key_arn]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.guardduty_detector_arn]
    }
  }
}

resource "aws_guardduty_publishing_destination" "this" {
  for_each = local.export_regions

  region          = each.key
  detector_id     = data.aws_guardduty_detector.existing[each.key].id
  destination_arn = local.destination_arn
  kms_key_arn     = var.guardduty_findings_kms_key_arn

  tags = {
    Name        = "${var.project}-guardduty-export-${each.key}"
    Project     = var.project
    Environment = var.environment
    Service     = "GuardDuty-Monitoring"
    ManagedBy   = "Terraform"
  }
}