data "aws_region" "current" {}

# -------------------------------------------------------
# Lambda package
# -------------------------------------------------------

data "archive_file" "dashboard_api_zip" {
  type        = "zip"
  source_dir  = "${local.rel_path_root}/lambda_code/dashboard_api"
  output_path = "${local.rel_path_root}/build/TrailAlertsDashboardApi.zip"
  excludes    = ["__pycache__", "tests"]
}

# -------------------------------------------------------
# IAM Role & Policy
# -------------------------------------------------------

resource "aws_iam_role" "dashboard_api_role" {
  name = "${var.project}-dashboard-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = { Service = "lambda.amazonaws.com" }
        Effect    = "Allow"
      }
    ]
  })
}

resource "aws_iam_role_policy" "dashboard_api_policy" {
  name = "${var.project}-dashboard-api-policy"
  role = aws_iam_role.dashboard_api_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # CloudWatch Logs
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "arn:aws:logs:*:*:*"
        },
        # S3 — read/write sigma rules
        {
          Effect = "Allow"
          Action = [
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:HeadObject"
          ]
          Resource = [
            var.rules_bucket_arn,
            "${var.rules_bucket_arn}/*"
          ]
        }
      ],
      # DynamoDB — read-only for alert history (conditional)
      var.dynamodb_table_arn != "" ? [
        {
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:Query",
            "dynamodb:Scan"
          ]
          Resource = [
            var.dynamodb_table_arn,
            "${var.dynamodb_table_arn}/index/*"
          ]
        }
      ] : []
    )
  })
}

# -------------------------------------------------------
# Lambda Function
# -------------------------------------------------------

resource "aws_lambda_function" "dashboard_api" {
  function_name = "${var.project}-dashboard-api"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  role          = aws_iam_role.dashboard_api_role.arn
  layers        = [var.lambda_layer_arn]
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.dashboard_api_zip.output_path
  source_code_hash = data.archive_file.dashboard_api_zip.output_base64sha256

  environment {
    variables = {
      RULES_BUCKET        = var.rules_bucket_name
      DYNAMODB_TABLE_NAME = var.dynamodb_table_name
      ENVIRONMENT         = var.environment
    }
  }
}

resource "aws_cloudwatch_log_group" "dashboard_api_log_group" {
  name              = "/aws/lambda/${var.project}-dashboard-api"
  retention_in_days = var.cloudwatch_logs_retention_days
}

# -------------------------------------------------------
# API Gateway HTTP API
# -------------------------------------------------------

resource "aws_apigatewayv2_api" "dashboard" {
  name          = "${var.project}-dashboard-api"
  protocol_type = "HTTP"

  dynamic "cors_configuration" {
    for_each = length(var.cors_allowed_origins) > 0 ? [1] : []

    content {
      allow_origins = var.cors_allowed_origins
      allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
      allow_headers = ["Content-Type", "Authorization"]
      max_age       = 3600
    }
  }
}

# JWT Authorizer — validates Cognito tokens on EVERY route
resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.dashboard.id
  name             = "${var.project}-cognito-authorizer"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    issuer   = "https://${var.cognito_user_pool_endpoint}"
    audience = [var.cognito_spa_client_id]
  }
}

# Lambda integration
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.dashboard.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.dashboard_api.invoke_arn
  payload_format_version = "2.0"
}

# Catch-all route with JWT auth — all requests must be authenticated
resource "aws_apigatewayv2_route" "default" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "$default"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

# Auto-deploy stage
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.dashboard.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw_log_group.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      authorizer     = "$context.authorizer.error"
    })
  }
}

resource "aws_cloudwatch_log_group" "api_gw_log_group" {
  name              = "/aws/apigateway/${var.project}-dashboard-api"
  retention_in_days = var.cloudwatch_logs_retention_days
}

# Permission for API GW to invoke Lambda
resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dashboard_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.dashboard.execution_arn}/*/*"
}
