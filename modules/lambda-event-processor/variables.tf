variable "project" {}
variable "email_endpoint" {}
variable "enable_sns" {}
variable "correlation_enabled" {}
variable "source_email" {}
variable "vpnapi_key" {
  sensitive = true
}
variable "vpnapi_key_secret_arn" {
  description = "Optional Secrets Manager secret ARN containing the VPN API key. When set, VPNAPI_KEY is not stored in the Lambda environment."
  type        = string
  default     = ""
}
variable "notification_cooldown_minutes" {}
variable "min_notification_severity" {}
variable "environment" {}
variable "cloudwatch_logs_retention_days" {}
variable "security_events_table_arn" {}
variable "security_events_table_name" {}
variable "trailalerts_rules_bucket_arn" {}
variable "trailalerts_rules_bucket" {}
variable "trailalerts_alerts_queue_arn" {}
variable "trailalerts_detection_layer_arn" {}
variable "trailalerts_alerts_topic_arn" {}
variable "webhook_url" {
  sensitive = true
}
variable "webhook_url_secret_arn" {
  description = "Optional Secrets Manager secret ARN containing the webhook URL. When set, WEBHOOK_URL is not stored in the Lambda environment."
  type        = string
  default     = ""
}
variable "webhook_headers" {
  sensitive = true
}
variable "webhook_headers_secret_arn" {
  description = "Optional Secrets Manager secret ARN containing webhook headers as a JSON object. When set, WEBHOOK_HEADERS is not stored in the Lambda environment."
  type        = string
  default     = ""
}