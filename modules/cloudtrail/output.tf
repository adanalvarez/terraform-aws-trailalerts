output "trailalerts_cloudtrail_bucket_arn" {
  description = "The name of the S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "trailalerts_cloudtrail_bucket_name" {
  description = "The name of the S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "cloudtrail_logs_kms_key_arn" {
  description = "The ARN of the KMS key used to encrypt CloudTrail logs"
  value       = aws_kms_key.cloudtrail_logs.arn
}