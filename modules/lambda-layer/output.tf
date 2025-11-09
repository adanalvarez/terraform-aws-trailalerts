output "trailalerts_detection_layer_arn" {
  description = "The ARN of the TrailAlerts detection Lambda layer"
  value       = aws_lambda_layer_version.trailalerts_detection_layer.arn
}