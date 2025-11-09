resource "aws_sns_topic" "trailalerts_alerts_topic" {
  name = "${var.project}-cloudtrail-alerts"
}

# Email subscription for security notifications
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.trailalerts_alerts_topic.arn
  protocol  = "email"
  endpoint  = var.email_endpoint
}

# Security policy restricting publishing permissions to the SNS topic
data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    resources = [aws_sns_topic.trailalerts_alerts_topic.arn]
  }
}

# Attach the security policy to the SNS topic
resource "aws_sns_topic_policy" "trailalerts_alerts_policy" {
  arn    = aws_sns_topic.trailalerts_alerts_topic.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}