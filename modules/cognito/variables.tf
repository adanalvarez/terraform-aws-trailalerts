variable "project" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "dashboard_admin_emails" {
  description = "Email addresses for initial dashboard admin users"
  type        = list(string)
}

variable "callback_urls" {
  description = "Allowed callback URLs for Cognito hosted UI"
  type        = list(string)
}

variable "logout_urls" {
  description = "Allowed logout URLs for Cognito hosted UI"
  type        = list(string)
}
