variable "project" {
  description = "The name of the project for tagging and identification."
  type        = string
}

variable "environment" {
  description = "Deployment environment identifier for tagging."
  type        = string
}

variable "guardduty_export_regions" {
  description = "AWS regions where existing GuardDuty detectors should export findings to the central TrailAlerts findings bucket."
  type        = list(string)

  validation {
    condition     = length(var.guardduty_export_regions) > 0
    error_message = "guardduty_export_regions must contain at least one region."
  }

  validation {
    condition     = length(var.guardduty_export_regions) == length(distinct(var.guardduty_export_regions))
    error_message = "guardduty_export_regions must not contain duplicate regions."
  }
}

variable "guardduty_findings_bucket_arn" {
  description = "ARN of the central S3 bucket where GuardDuty should export findings."
  type        = string

  validation {
    condition     = var.guardduty_findings_bucket_arn != ""
    error_message = "guardduty_findings_bucket_arn must not be empty."
  }
}

variable "guardduty_findings_kms_key_arn" {
  description = "ARN of the KMS key GuardDuty uses to encrypt exported findings. GuardDuty requires exported findings to be encrypted."
  type        = string

  validation {
    condition     = var.guardduty_findings_kms_key_arn != ""
    error_message = "guardduty_findings_kms_key_arn must not be empty."
  }
}

variable "guardduty_export_destination_prefix" {
  description = "Optional destination prefix appended to the GuardDuty export bucket ARN. Leave null to use GuardDuty's AWSLogs/<account-id>/GuardDuty/<region>/ default layout."
  type        = string
  default     = null
}
