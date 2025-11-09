resource "null_resource" "create_zip_every_time" {
  triggers = {
    always_run = timestamp()
  }
}

data "archive_file" "trailalerts_event_processor_zip" {
  depends_on  = [null_resource.create_zip_every_time]
  type        = "zip"
  source_dir  = "${local.rel_path_root}/lambda_code/event_processor"
  output_path = "${local.rel_path_root}/build/TrailAlertsEventProcessor.zip"
}

resource "aws_lambda_function" "trailalerts_event_processor" {
  function_name = "${var.project}-event-processor"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  layers        = [var.trailalerts_detection_layer_arn]
  role          = aws_iam_role.trailalerts_event_processor_role.arn
  timeout       = 120
  memory_size   = 512

  filename         = data.archive_file.trailalerts_event_processor_zip.output_path
  source_code_hash = data.archive_file.trailalerts_event_processor_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE_NAME           = var.correlation_enabled ? var.security_events_table_name : ""
      SNS_TOPIC_ARN                 = var.trailalerts_alerts_topic_arn
      EMAIL_RECIPIENT               = var.email_endpoint
      SOURCE_EMAIL                  = var.source_email
      VPNAPI_KEY                    = var.vpnapi_key
      CORRELATION_ENABLED           = tostring(var.correlation_enabled)
      CORRELATION_RULES_BUCKET      = var.trailalerts_rules_bucket_arn
      NOTIFICATION_COOLDOWN_MINUTES = tostring(var.notification_cooldown_minutes)
      MIN_NOTIFICATION_SEVERITY     = var.min_notification_severity
    }
  }

}

resource "aws_iam_role" "trailalerts_event_processor_role" {
  name = "${var.project}-event-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = { Service = "lambda.amazonaws.com" }
        Effect    = "Allow"
        Sid       = ""
      }
    ]
  })

  tags = {
    Name        = "TrailAlerts Event Processor Lambda Role"
    Environment = var.environment
    Service     = "CloudTrail-Monitoring"
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "trailalerts_event_processor_policy" {
  name = "${var.project}-event-processor-policy"
  role = aws_iam_role.trailalerts_event_processor_role.id

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
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = var.trailalerts_alerts_queue_arn
      },
      {
        Effect   = "Allow"
        Action   = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["s3:ListBucket", "s3:GetObject"]
        Resource = [
          var.trailalerts_rules_bucket_arn,
          "${var.trailalerts_rules_bucket_arn}/*"
        ]
      }
      ],
      var.correlation_enabled ? [{
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = [
          var.security_events_table_arn,
          "${var.security_events_table_arn}/index/*"
        ]
    }] : [])
  })
}

resource "aws_lambda_event_source_mapping" "sqs_to_event_processor" {
  event_source_arn                   = var.trailalerts_alerts_queue_arn
  function_name                      = aws_lambda_function.trailalerts_event_processor.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 60
}

resource "aws_cloudwatch_log_group" "trailalerts_event_processor_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.trailalerts_event_processor.function_name}"
  retention_in_days = var.cloudwatch_logs_retention_days
}

resource "aws_iam_role_policy" "trailalerts_event_processor_sqs_policy" {
  name = "${var.project}-event-processor-sqs-policy"
  role = aws_iam_role.trailalerts_event_processor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = var.trailalerts_alerts_queue_arn
      }
    ]
  })
}

# IAM policy document for Lambda roles to publish to SNS
data "aws_iam_policy_document" "sns_topic_policy_role" {
  count = var.enable_sns ? 1 : 0

  statement {
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [var.trailalerts_alerts_topic_arn]
  }
}

# Attach the publishing permissions to the event processor role
resource "aws_iam_role_policy" "sns_topic_policy" {
  count = var.enable_sns ? 1 : 0

  name = "sns_topic_policy"
  role = aws_iam_role.trailalerts_event_processor_role.id

  policy = data.aws_iam_policy_document.sns_topic_policy_role[0].json
}