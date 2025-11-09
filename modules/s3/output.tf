output "trailalerts_rules_bucket_arn" {
  description = "The ARN of the S3 bucket for TrailAlerts rules"
  value       = aws_s3_bucket.trailalerts_rules_bucket.arn
}

output "trailalerts_rules_bucket_name" {
  description = "The name of the S3 bucket for TrailAlerts rules"
  value       = aws_s3_bucket.trailalerts_rules_bucket.bucket
}