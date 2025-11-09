output "trailalerts_alerts_queue_arn" {
  description = "The ARN of the SQS queue for security alerts"
  value       = aws_sqs_queue.trailalerts_alerts_queue.arn
}

output "trailalerts_alerts_queue_url" {
  description = "The URL of the SQS queue for security alerts"
  value       = aws_sqs_queue.trailalerts_alerts_queue.url
}