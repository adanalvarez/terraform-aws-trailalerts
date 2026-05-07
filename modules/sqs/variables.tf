variable "project" {}

variable "kms_master_key_id" {
  description = "KMS key ID or alias used to encrypt the alerts SQS queue. Defaults to the AWS-managed SQS key."
  type        = string
  default     = "alias/aws/sqs"
}