output "trailalerts_alerts_topic_arn" {
  description = "The ARN of the SNS topic for security alerts"
  value       = aws_sns_topic.trailalerts_alerts_topic.arn
}