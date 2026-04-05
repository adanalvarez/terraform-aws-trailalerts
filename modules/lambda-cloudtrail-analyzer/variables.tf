variable "project" {}
variable "environment" {}
variable "cloudwatch_logs_retention_days" {}
variable "cloudtrail_bucket_id" {}
variable "cloudtrail_bucket_arn" {}
variable "trailalerts_rules_bucket_arn" {}
variable "trailalerts_alerts_queue_arn" {}
variable "trailalerts_alerts_queue_url" {}
variable "trailalerts_detection_layer_arn" {}
variable "trailalerts_rules_bucket" {}

variable "analyzer_memory_size" {
  description = "Memory size in MB for the CloudTrail analyzer Lambda. CPU scales linearly with memory; 1769 MB = 1 full vCPU."
  type        = number
  default     = 1024

  validation {
    condition     = var.analyzer_memory_size >= 128 && var.analyzer_memory_size <= 10240
    error_message = "analyzer_memory_size must be between 128 and 10240 MB, inclusive, to be a valid AWS Lambda memory size."
  }
}

variable "analyzer_timeout" {
  description = "Timeout in seconds for the CloudTrail analyzer Lambda."
  type        = number
  default     = 60

  validation {
    condition     = var.analyzer_timeout > 0 && var.analyzer_timeout <= 900
    error_message = "analyzer_timeout must be greater than 0 and less than or equal to 900 seconds (the AWS Lambda maximum timeout)."
  }
}