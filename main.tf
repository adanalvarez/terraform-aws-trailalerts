module "cloudtrail" {
  source = "./modules/cloudtrail"
  count  = var.create_cloudtrail ? 1 : 0

  project                       = var.project
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region_trail
}

module "dynamodb" {
  source = "./modules/dynamodb"
  count  = var.correlation_enabled ? 1 : 0

  project = var.project
}


module "sqs" {
  source = "./modules/sqs"

  project = var.project
}

module "s3" {
  source = "./modules/s3"

  project = var.project
}

module "lambda_layer" {
  source  = "./modules/lambda-layer"
  project = var.project
}

module "sns" {
  source = "./modules/sns"
  count  = var.enable_sns ? 1 : 0

  project        = var.project
  email_endpoint = var.email_endpoint
}

module "lambda_event_processor" {
  source = "./modules/lambda-event-processor"

  project                         = var.project
  enable_sns                      = var.enable_sns
  email_endpoint                  = var.email_endpoint
  correlation_enabled             = var.correlation_enabled
  source_email                    = var.source_email
  vpnapi_key                      = var.vpnapi_key
  notification_cooldown_minutes   = var.notification_cooldown_minutes
  min_notification_severity       = var.min_notification_severity
  environment                     = var.environment
  cloudwatch_logs_retention_days  = var.cloudwatch_logs_retention_days
  security_events_table_arn       = var.correlation_enabled ? module.dynamodb[0].security_events_table_arn : ""
  security_events_table_name      = var.correlation_enabled ? module.dynamodb[0].security_events_table_name : ""
  trailalerts_rules_bucket_arn    = module.s3.trailalerts_rules_bucket_arn
  trailalerts_rules_bucket        = module.s3.trailalerts_rules_bucket_name
  trailalerts_alerts_queue_arn    = module.sqs.trailalerts_alerts_queue_arn
  trailalerts_detection_layer_arn = module.lambda_layer.trailalerts_detection_layer_arn
  trailalerts_alerts_topic_arn    = var.enable_sns ? module.sns[0].trailalerts_alerts_topic_arn : ""
  webhook_url                     = var.webhook_url
  webhook_headers                 = var.webhook_headers
}


data "aws_s3_bucket" "existing_cloudtrail_logs" {
  count  = var.create_cloudtrail ? 0 : 1
  bucket = var.existing_cloudtrail_bucket_name
}


module "lambda_cloudtrail_analyzer" {
  source = "./modules/lambda-cloudtrail-analyzer"

  project                         = var.project
  environment                     = var.environment
  cloudwatch_logs_retention_days  = var.cloudwatch_logs_retention_days
  cloudtrail_bucket_id            = var.create_cloudtrail ? module.cloudtrail[0].trailalerts_cloudtrail_bucket_name : data.aws_s3_bucket.existing_cloudtrail_logs[0].id
  cloudtrail_bucket_arn           = var.create_cloudtrail ? module.cloudtrail[0].trailalerts_cloudtrail_bucket_arn : data.aws_s3_bucket.existing_cloudtrail_logs[0].arn
  trailalerts_rules_bucket_arn    = module.s3.trailalerts_rules_bucket_arn
  trailalerts_alerts_queue_arn    = module.sqs.trailalerts_alerts_queue_arn
  trailalerts_alerts_queue_url    = module.sqs.trailalerts_alerts_queue_url
  trailalerts_detection_layer_arn = module.lambda_layer.trailalerts_detection_layer_arn
  trailalerts_rules_bucket        = module.s3.trailalerts_rules_bucket_name
}

# ---------------------------------------------------------------------------
# Dashboard (optional) — Cognito + API Gateway + Lambda + S3/CloudFront
# ---------------------------------------------------------------------------

module "cognito" {
  source = "./modules/cognito"
  count  = var.enable_dashboard ? 1 : 0

  project                = var.project
  environment            = var.environment
  dashboard_admin_emails = var.dashboard_admin_emails

  # Placeholder URLs — updated by null_resource after CloudFront is created
  callback_urls = ["https://placeholder.invalid/"]
  logout_urls   = ["https://placeholder.invalid/"]
}

# Update Cognito client callback URLs with the real CloudFront domain after creation.
# This avoids a circular dependency between the Cognito and CloudFront modules.
resource "null_resource" "update_cognito_callbacks" {
  count = var.enable_dashboard ? 1 : 0

  triggers = {
    cloudfront_domain = module.dashboard_frontend[0].cloudfront_distribution_domain
    client_id         = module.cognito[0].spa_client_id
    user_pool_id      = module.cognito[0].user_pool_id
  }

  provisioner "local-exec" {
    command = <<-EOF
      aws cognito-idp update-user-pool-client \
        --region "${var.aws_region}" \
        --user-pool-id "${module.cognito[0].user_pool_id}" \
        --client-id "${module.cognito[0].spa_client_id}" \
        --callback-urls "https://${module.dashboard_frontend[0].cloudfront_distribution_domain}/" \
        --logout-urls "https://${module.dashboard_frontend[0].cloudfront_distribution_domain}/" \
        --allowed-o-auth-flows code \
        --allowed-o-auth-scopes openid email profile \
        --supported-identity-providers COGNITO \
        --allowed-o-auth-flows-user-pool-client \
        --explicit-auth-flows ALLOW_REFRESH_TOKEN_AUTH ALLOW_USER_SRP_AUTH ALLOW_USER_PASSWORD_AUTH \
        --prevent-user-existence-errors ENABLED \
        --access-token-validity 1 \
        --id-token-validity 1 \
        --refresh-token-validity 30 \
        --token-validity-units '{"AccessToken":"hours","IdToken":"hours","RefreshToken":"days"}'
    EOF
  }
}

module "dashboard_api" {
  source = "./modules/dashboard-api"
  count  = var.enable_dashboard ? 1 : 0

  project                        = var.project
  environment                    = var.environment
  cloudwatch_logs_retention_days = var.cloudwatch_logs_retention_days
  rules_bucket_name              = module.s3.trailalerts_rules_bucket_name
  rules_bucket_arn               = module.s3.trailalerts_rules_bucket_arn
  dynamodb_table_name            = var.correlation_enabled ? module.dynamodb[0].security_events_table_name : ""
  dynamodb_table_arn             = var.correlation_enabled ? module.dynamodb[0].security_events_table_arn : ""
  cognito_user_pool_arn          = module.cognito[0].user_pool_arn
  cognito_user_pool_endpoint     = module.cognito[0].user_pool_endpoint
  cognito_spa_client_id          = module.cognito[0].spa_client_id
  lambda_layer_arn               = module.lambda_layer.trailalerts_detection_layer_arn
}

module "dashboard_frontend" {
  source = "./modules/dashboard-frontend"
  count  = var.enable_dashboard ? 1 : 0

  project               = var.project
  environment           = var.environment
  api_endpoint          = module.dashboard_api[0].api_endpoint
  cognito_user_pool_id  = module.cognito[0].user_pool_id
  cognito_spa_client_id = module.cognito[0].spa_client_id
  cognito_domain        = module.cognito[0].user_pool_domain
}
