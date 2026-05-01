variable "project" {}
variable "environment" {}
variable "cloudwatch_logs_retention_days" {}
variable "trailalerts_alerts_queue_arn" {}
variable "trailalerts_alerts_queue_url" {}
variable "guardduty_findings_bucket_id" {}
variable "guardduty_findings_bucket_arn" {}

variable "guardduty_findings_prefix" {
  description = "Optional S3 object key prefix used to limit GuardDuty ingester Lambda invocations. GuardDuty exports usually use AWSLogs/<account-id>/GuardDuty/<region>/ when no custom destination prefix is set."
  type        = string
  default     = null
}

variable "guardduty_findings_filter_suffix" {
  description = "S3 object key suffix used to limit GuardDuty ingester Lambda invocations. GuardDuty S3 exports are gzip-compressed JSON Lines by default."
  type        = string
  default     = ".jsonl.gz"
}

variable "guardduty_min_severity" {
  description = "Minimum numeric GuardDuty severity to ingest. Use 0 to ingest all findings, 4 for medium and higher, or 7 for high findings only."
  type        = number
  default     = 0

  validation {
    condition     = var.guardduty_min_severity >= 0 && var.guardduty_min_severity <= 10
    error_message = "guardduty_min_severity must be between 0 and 10."
  }
}

variable "guardduty_include_archived" {
  description = "Whether archived GuardDuty findings should be ingested. Leave false to process only active findings."
  type        = bool
  default     = false
}

variable "guardduty_findings_kms_key_arn" {
  description = "Optional KMS key ARN used to encrypt GuardDuty exported findings. Set this when the Lambda role needs kms:Decrypt for the export bucket objects."
  type        = string
  default     = ""
}

variable "guardduty_manage_bucket_notification" {
  description = "Whether this module should manage the S3 bucket notification that invokes the GuardDuty ingester. Disable when another Terraform resource already owns notifications for the same bucket."
  type        = bool
  default     = true
}

variable "guardduty_ingester_memory_size" {
  description = "Memory size in MB for the GuardDuty ingester Lambda."
  type        = number
  default     = 512

  validation {
    condition     = var.guardduty_ingester_memory_size >= 128 && var.guardduty_ingester_memory_size <= 10240
    error_message = "guardduty_ingester_memory_size must be between 128 and 10240 MB."
  }
}

variable "guardduty_ingester_timeout" {
  description = "Timeout in seconds for the GuardDuty ingester Lambda."
  type        = number
  default     = 60

  validation {
    condition     = var.guardduty_ingester_timeout > 0 && var.guardduty_ingester_timeout <= 900
    error_message = "guardduty_ingester_timeout must be greater than 0 and less than or equal to 900 seconds."
  }
}
