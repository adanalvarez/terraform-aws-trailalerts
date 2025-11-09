resource "null_resource" "create_zip_every_time" {
  triggers = {
    always_run = timestamp()
  }
}

data "archive_file" "trailalerts_cloudtrail_analyzer_zip" {
  depends_on  = [null_resource.create_zip_every_time]
  type        = "zip"
  source_dir  = "${local.rel_path_root}/lambda_code/cloudtrail_analyzer"
  output_path = "${local.rel_path_root}/build/TrailAlertsCloudTrailAnalyzer.zip"
}

# Create Lambda role
resource "aws_iam_role" "trailalerts_cloudtrail_analyzer_role" {
  name = "${var.project}-cloudtrail-analyzer-role"

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

}

# Attach inline policy to Lambda role
resource "aws_iam_role_policy" "trailalerts_cloudtrail_analyzer_policy" {
  name = "${var.project}-cloudtrail-analyzer-policy"
  role = aws_iam_role.trailalerts_cloudtrail_analyzer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
        Action   = ["s3:GetObject"]
        Resource = "${var.cloudtrail_bucket_arn}/*"
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          var.trailalerts_rules_bucket_arn,
          "${var.trailalerts_rules_bucket_arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = var.trailalerts_alerts_queue_arn
      }
    ]
  })
}

resource "aws_lambda_function" "trailalerts_cloudtrail_analyzer" {
  function_name = "${var.project}-cloudtrail-analyzer"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  role          = aws_iam_role.trailalerts_cloudtrail_analyzer_role.arn
  layers        = [var.trailalerts_detection_layer_arn]
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.trailalerts_cloudtrail_analyzer_zip.output_path
  source_code_hash = data.archive_file.trailalerts_cloudtrail_analyzer_zip.output_base64sha256

  environment {
    variables = {
      SQS_QUEUE_URL      = var.trailalerts_alerts_queue_url
      TRAILALERTS_BUCKET = var.trailalerts_rules_bucket
      ENVIRONMENT        = var.environment
    }
  }
}

# Trigger Lambda when new logs appear in the CloudTrail bucket
resource "aws_s3_bucket_notification" "cloudtrail_logs_notification" {
  bucket = var.cloudtrail_bucket_id

  lambda_function {
    lambda_function_arn = aws_lambda_function.trailalerts_cloudtrail_analyzer.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [
    aws_lambda_function.trailalerts_cloudtrail_analyzer,
    aws_lambda_permission.allow_s3
  ]
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trailalerts_cloudtrail_analyzer.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = var.cloudtrail_bucket_arn
}

resource "aws_cloudwatch_log_group" "trailalerts_cloudtrail_analyzer_log_group" {
  name              = "/aws/lambda/trailalerts-cloudtrail-analyzer"
  retention_in_days = var.cloudwatch_logs_retention_days
}

# Policy allowing the CloudTrail Analyzer Lambda to publish security events to SQS
resource "aws_iam_role_policy" "trailalerts_cloudtrail_analyzer_sqs_policy" {
  name = "${var.project}-cloudtrail-analyzer-sqs-policy"
  role = aws_iam_role.trailalerts_cloudtrail_analyzer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = var.trailalerts_alerts_queue_arn
      }
    ]
  })
}