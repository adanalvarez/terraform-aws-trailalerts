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
