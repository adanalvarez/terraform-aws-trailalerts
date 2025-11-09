module "trailalerts" {
  source = "../../"

  aws_region                      = var.region
  email_endpoint                  = "mail@example.com"
  create_cloudtrail               = false
  existing_cloudtrail_bucket_name = "aws-cloudtrail-logs-123456789"
  enable_sns                      = false
  source_email                    = "mail@example.com"
  ses_identities                  = ["mail@example.com"]
  correlation_enabled             = true
  environment                     = "test"
  cloudwatch_logs_retention_days  = 30
  notification_cooldown_minutes   = 5

}