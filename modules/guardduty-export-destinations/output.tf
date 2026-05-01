output "guardduty_export_destination_arn" {
  description = "S3 destination ARN used by GuardDuty publishing destinations, including the optional prefix when configured."
  value       = local.destination_arn
}

output "guardduty_export_destination_ids" {
  description = "GuardDuty publishing destination IDs keyed by region."
  value       = { for region, destination in aws_guardduty_publishing_destination.this : region => destination.destination_id }
}

output "guardduty_export_destination_arns" {
  description = "GuardDuty publishing destination ARNs keyed by region."
  value       = { for region, destination in aws_guardduty_publishing_destination.this : region => destination.arn }
}

output "guardduty_export_bucket_policy_json" {
  description = "Policy document that can be merged into the central GuardDuty export bucket policy."
  value       = data.aws_iam_policy_document.guardduty_export_bucket.json
}

output "guardduty_export_kms_key_policy_json" {
  description = "Policy document that can be merged into the GuardDuty export KMS key policy."
  value       = data.aws_iam_policy_document.guardduty_export_kms.json
}