data "archive_file" "trailalerts_guardduty_ingester_zip" {
  type        = "zip"
  source_dir  = "${local.rel_path_root}/lambda_code/guardduty_ingester"
  output_path = "${local.rel_path_root}/build/TrailAlertsGuardDutyIngester.zip"
  excludes    = ["__pycache__", "tests"]
}

resource "aws_iam_role" "trailalerts_guardduty_ingester_role" {
  name = "${var.project}-guardduty-ingester-role"

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

  tags = {
    Name        = "TrailAlerts GuardDuty Ingester Lambda Role"
    Environment = var.environment
    Service     = "GuardDuty-Monitoring"
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "trailalerts_guardduty_ingester_policy" {
  name = "${var.project}-guardduty-ingester-policy"
  role = aws_iam_role.trailalerts_guardduty_ingester_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${var.guardduty_findings_bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = var.trailalerts_alerts_queue_arn
      }
      ],
      var.guardduty_findings_kms_key_arn != "" ? [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = var.guardduty_findings_kms_key_arn
    }] : [])
  })
}

resource "aws_lambda_function" "trailalerts_guardduty_ingester" {
  function_name = "${var.project}-guardduty-ingester"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  role          = aws_iam_role.trailalerts_guardduty_ingester_role.arn
  timeout       = var.guardduty_ingester_timeout
  memory_size   = var.guardduty_ingester_memory_size

  filename         = data.archive_file.trailalerts_guardduty_ingester_zip.output_path
  source_code_hash = data.archive_file.trailalerts_guardduty_ingester_zip.output_base64sha256

  environment {
    variables = {
      SQS_QUEUE_URL              = var.trailalerts_alerts_queue_url
      GUARDDUTY_MIN_SEVERITY     = tostring(var.guardduty_min_severity)
      GUARDDUTY_INCLUDE_ARCHIVED = tostring(var.guardduty_include_archived)
      GUARD_DUTY_FINDINGS_PREFIX = var.guardduty_findings_prefix != null ? var.guardduty_findings_prefix : ""
      GUARD_DUTY_FINDINGS_SUFFIX = var.guardduty_findings_filter_suffix
      GUARD_DUTY_FINDINGS_BUCKET = var.guardduty_findings_bucket_id
    }
  }
}

resource "aws_lambda_permission" "allow_guardduty_findings_s3" {
  count = var.guardduty_manage_bucket_notification ? 1 : 0

  statement_id  = "AllowExecutionFromGuardDutyFindingsBucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trailalerts_guardduty_ingester.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = var.guardduty_findings_bucket_arn
}

resource "aws_s3_bucket_notification" "guardduty_findings_notification" {
  count = var.guardduty_manage_bucket_notification ? 1 : 0

  bucket = var.guardduty_findings_bucket_id

  lambda_function {
    lambda_function_arn = aws_lambda_function.trailalerts_guardduty_ingester.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = var.guardduty_findings_prefix
    filter_suffix       = var.guardduty_findings_filter_suffix
  }

  depends_on = [aws_lambda_permission.allow_guardduty_findings_s3]
}

resource "aws_cloudwatch_log_group" "trailalerts_guardduty_ingester_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.trailalerts_guardduty_ingester.function_name}"
  retention_in_days = var.cloudwatch_logs_retention_days
}
