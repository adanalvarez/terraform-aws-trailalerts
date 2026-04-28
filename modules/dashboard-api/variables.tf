variable "project" {}
variable "environment" {}
variable "cloudwatch_logs_retention_days" {}
variable "rules_bucket_name" {}
variable "rules_bucket_arn" {}
variable "dynamodb_table_name" {
  default = ""
}
variable "dynamodb_table_arn" {
  default = ""
}
variable "cognito_user_pool_arn" {}
variable "cognito_user_pool_endpoint" {}
variable "cognito_spa_client_id" {}
variable "lambda_layer_arn" {}

variable "cors_allowed_origins" {
  description = "Optional CORS origins for direct browser access to the dashboard API. Leave empty when the dashboard uses the same-origin CloudFront /api/* proxy."
  type        = list(string)
  default     = []
}
