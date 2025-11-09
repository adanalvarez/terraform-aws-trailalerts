variable "project" {
  description = "The name of the project for tagging and identification"
  type        = string
  default     = "TrailAlerts"
}

variable "aws_region" {
  description = "The AWS region where all resources will be deployed"
  type        = string
}

variable "email_endpoint" {
  description = "Email address that will receive security notifications and alerts"
  type        = string
}

variable "create_cloudtrail" {
  description = "Whether to create CloudTrail and S3 bucket or use existing"
  type        = bool
  default     = true
}

variable "existing_cloudtrail_bucket_name" {
  description = "Name of existing CloudTrail bucket when create_cloudtrail is false"
  type        = string
  default     = ""
}

variable "enable_sns" {
  description = "Whether to create SNS topic and subscription"
  type        = bool
  default     = true
}

variable "ses_identities" {
  description = "List of SES identities to verify and use for email notifications"
  type        = list(string)
  default     = []
}
variable "source_email" {
  description = "Email address to use as the source for email notifications"
  type        = string
  default     = ""
}
variable "vpnapi_key" {
  description = "API key for VPN service integration"
  type        = string
  default     = ""
}

variable "correlation_enabled" {
  type        = bool
  default     = false
  description = "Whether to enable event correlation analysis - creates a DynamoDB table for storing and analyzing security events"
}

variable "environment" {
  description = "Deployment environment identifier (e.g., dev, prod, staging) for resource tagging and isolation"
  type        = string
  default     = "dev"
}

variable "cloudwatch_logs_retention_days" {
  description = "Number of days to retain CloudWatch logs before automatic deletion"
  type        = number
  default     = 30
}

variable "notification_cooldown_minutes" {
  description = "Cooldown period in minutes between notifications for the same rule to prevent alert fatigue"
  type        = number
  default     = 60
}

variable "min_notification_severity" {
  description = "Minimum severity threshold for sending notifications (critical, high, medium, low, info)"
  type        = string
  default     = "medium"
  validation {
    condition     = contains(["critical", "high", "medium", "low", "info"], var.min_notification_severity)
    error_message = "The min_notification_severity value must be one of: critical, high, medium, low, info."
  }
}

variable "include_global_service_events" {
  description = "Whether to include global service events in CloudTrail logs"
  type        = bool
  default     = true
}

variable "is_multi_region_trail" {
  description = "Whether the CloudTrail should log events for all regions"
  type        = bool
  default     = true
}