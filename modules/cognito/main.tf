resource "aws_cognito_user_pool" "dashboard" {
  name = "${var.project}-dashboard-users"

  # Strong password policy
  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 1
  }

  # MFA configuration
  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  # Account recovery via verified email
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Auto-verify email
  auto_verified_attributes = ["email"]

  # Schema: require email
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 5
      max_length = 128
    }
  }

  # Block self-signup — admin creates users only
  admin_create_user_config {
    allow_admin_create_user_only = true

    invite_message_template {
      email_subject = "${var.project} Dashboard - Your account"
      email_message = "Your ${var.project} dashboard account has been created. Username: {username}, Temporary password: {####}"
      sms_message   = "Your ${var.project} dashboard username is {username} and temporary password is {####}"
    }
  }

  # Advanced security
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  tags = {
    Project     = var.project
    Environment = var.environment
  }
}

# Cognito hosted UI domain (uses random suffix for uniqueness)
resource "random_string" "cognito_domain_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_cognito_user_pool_domain" "dashboard" {
  domain       = lower("${var.project}-dashboard-${random_string.cognito_domain_suffix.result}")
  user_pool_id = aws_cognito_user_pool.dashboard.id
}

# App client for the SPA (public client, PKCE flow, no secret)
resource "aws_cognito_user_pool_client" "dashboard_spa" {
  name         = "${var.project}-dashboard-spa"
  user_pool_id = aws_cognito_user_pool.dashboard.id

  # Public client (SPA) — no client secret
  generate_secret = false

  # OAuth flows
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true
  supported_identity_providers         = ["COGNITO"]

  # Callback/logout URLs — placeholder; updated by null_resource after CloudFront creation
  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  # Token validity
  access_token_validity  = 1  # hours
  id_token_validity      = 1  # hours
  refresh_token_validity = 30 # days

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Security: prevent token leakage
  prevent_user_existence_errors = "ENABLED"

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_USER_PASSWORD_AUTH"
  ]

  # Callback/logout URLs are managed by null_resource after CloudFront creation
  lifecycle {
    ignore_changes = [callback_urls, logout_urls]
  }
}

# Cognito hosted UI branding
resource "aws_cognito_user_pool_ui_customization" "dashboard" {
  user_pool_id = aws_cognito_user_pool.dashboard.id
  client_id    = aws_cognito_user_pool_client.dashboard_spa.id

  css = <<-CSS
    .banner-customizable {
      background-color: #8ECAE6;
      padding: 24px 0;
    }

    .logo-customizable {
      max-width: 200px;
    }

    .background-customizable {
      background-color: #8ECAE6;
    }

    .submitButton-customizable {
      background-color: #01253D;
      border-color: #01253D;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      padding: 12px 24px;
    }

    .submitButton-customizable:hover {
      background-color: #17A2B8;
      border-color: #17A2B8;
    }

    .idpButton-customizable {
      background-color: #01253D;
      border-color: #01253D;
      border-radius: 10px;
      font-size: 15px;
    }

    .idpButton-customizable:hover {
      background-color: #17A2B8;
      border-color: #17A2B8;
    }

    .textDescription-customizable {
      color: #01253D;
      font-size: 15px;
    }

    .label-customizable {
      color: #2B2D31;
      font-weight: 500;
    }

    .inputField-customizable {
      border-color: #D1D5DB;
      border-radius: 6px;
      color: #2B2D31;
      padding: 10px 14px;
    }

    .inputField-customizable:focus {
      border-color: #17A2B8;
    }

    .redirect-customizable {
      color: #17A2B8;
    }

    .legalText-customizable {
      color: #6B7280;
    }

    .errorMessage-customizable {
      color: #dc2626;
    }
  CSS

  image_file = filebase64("${path.module}/../../images/TrailAlerts.png")

  depends_on = [aws_cognito_user_pool_domain.dashboard]
}

# Create initial admin user(s)
resource "aws_cognito_user" "admin" {
  for_each = toset(var.dashboard_admin_emails)

  user_pool_id = aws_cognito_user_pool.dashboard.id
  username     = each.value

  attributes = {
    email          = each.value
    email_verified = true
  }
}
