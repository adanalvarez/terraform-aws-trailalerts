############################
# SQS QUEUE FOR SECURITY ALERTS
############################

# Queue for security alerts - buffers detected security events before processing
resource "aws_sqs_queue" "trailalerts_alerts_queue" {
  name                       = "${var.project}-alerts-queue"
  message_retention_seconds  = 86400
  visibility_timeout_seconds = 180
  delay_seconds              = 0

}