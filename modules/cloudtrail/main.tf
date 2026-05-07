data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  cloudtrail_name       = "${var.project}-security-trail"
  cloudtrail_source_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}"
}

resource "aws_kms_key" "cloudtrail_logs" {
  description             = "KMS key for ${var.project} CloudTrail log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailGenerateDataKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "aws:SourceArn"                            = local.cloudtrail_source_arn
            "kms:EncryptionContext:aws:cloudtrail:arn" = local.cloudtrail_source_arn
          }
        }
      }
    ]
  })

  tags = {
    Name      = "${var.project}-cloudtrail-logs"
    Project   = var.project
    ManagedBy = "Terraform"
  }
}

resource "aws_kms_alias" "cloudtrail_logs" {
  name          = "alias/${lower(var.project)}-cloudtrail-logs"
  target_key_id = aws_kms_key.cloudtrail_logs.key_id
}

resource "aws_cloudtrail" "security_trail" {
  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region_trail
  kms_key_id                    = aws_kms_key.cloudtrail_logs.arn
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = lower("${var.project}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}")
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.bucket

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
      }
    ]
  })
}