data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "security_trail" {
  name                          = "${var.project}-security-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region_trail
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