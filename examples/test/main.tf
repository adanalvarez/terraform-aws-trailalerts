module "trailalerts" {
  source = "../../"

  aws_region                              = var.region
  email_endpoint                          = "adan.alvarez.90@gmail.com"
  create_cloudtrail                       = false
  existing_cloudtrail_bucket_name         = "trailalerts-cloudtrail-logs-728951503693"
  enable_sns                              = false
  source_email                            = "adan.alvarez.90@gmail.com"
  ses_identities                          = ["adan.alvarez.90@gmail.com"]
  correlation_enabled                     = true
  environment                             = "test"
  cloudwatch_logs_retention_days          = 30
  notification_cooldown_minutes           = 5
  enable_dashboard                        = true
  enable_guardduty_ingestion              = true
  existing_guardduty_findings_bucket_name = "guardduty-logs-728951503693"
  guardduty_findings_kms_key_arn          = "arn:aws:kms:us-east-1:728951503693:key/94027699-8258-489f-9b8f-0de79d644004"

  # Enable after importing existing manual GuardDuty publishing destinations, or when
  # creating destinations for regions that do not already export findings.
   enable_guardduty_export_destinations = true
   guardduty_export_regions = [
     "eu-west-1"
   ]
}