variable "project" {}
variable "email_endpoint" {}

variable "kms_master_key_id" {
  description = "KMS key ID or alias used to encrypt the alerts SNS topic. Defaults to the AWS-managed SNS key."
  type        = string
  default     = "alias/aws/sns"
}