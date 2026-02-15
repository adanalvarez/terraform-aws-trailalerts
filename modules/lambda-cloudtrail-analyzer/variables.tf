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
}

variable "analyzer_timeout" {
  description = "Timeout in seconds for the CloudTrail analyzer Lambda."
  type        = number
  default     = 60
}