module "trailalerts" {
  source = "../../"

  aws_region                              = var.region
  email_endpoint                          = "user@example.com"
  create_cloudtrail                       = false
  existing_cloudtrail_bucket_name         = "trailalerts-cloudtrail-logs-<account-id>"
  enable_sns                              = false
  source_email                            = "user@example.com"
  ses_identities                          = ["user@example.com"]
  correlation_enabled                     = true
  environment                             = "test"
  cloudwatch_logs_retention_days          = 30
  notification_cooldown_minutes           = 5
  enable_dashboard                        = true
  enable_guardduty_ingestion              = true
  existing_guardduty_findings_bucket_name = "guardduty-logs-<account-id>"
  guardduty_findings_kms_key_arn          = "arn:aws:kms:<region>:<account-id>:key/<uuid>"

  # Enable after importing existing manual GuardDuty publishing destinations, or when
  # creating destinations for regions that do not already export findings.
  enable_guardduty_export_destinations = true
  guardduty_export_regions = [
    "eu-west-1"
  ]
}