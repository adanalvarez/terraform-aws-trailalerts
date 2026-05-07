variable "project" {}
variable "environment" {}

variable "api_endpoint" {
  description = "API Gateway endpoint URL"
}

variable "cognito_user_pool_id" {}
variable "cognito_spa_client_id" {}
variable "cognito_domain" {}

variable "cloudfront_aliases" {
  description = "Optional custom domain aliases for the dashboard CloudFront distribution. Requires cloudfront_acm_certificate_arn."
  type        = list(string)
  default     = []
}

variable "cloudfront_acm_certificate_arn" {
  description = "Optional ACM certificate ARN in us-east-1 for dashboard custom domains. Enables configurable TLS minimum protocol version."
  type        = string
  default     = ""
}

variable "cloudfront_minimum_protocol_version" {
  description = "Minimum TLS security policy for dashboard CloudFront custom certificates. Used only when cloudfront_acm_certificate_arn is set."
  type        = string
  default     = "TLSv1.2_2021"

  validation {
    condition     = contains(["TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021"], var.cloudfront_minimum_protocol_version)
    error_message = "cloudfront_minimum_protocol_version must be one of TLSv1.2_2018, TLSv1.2_2019, or TLSv1.2_2021."
  }
}
