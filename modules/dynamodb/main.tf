resource "aws_dynamodb_table" "security_events" {
  name         = "${var.project}-security-events"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "pk"
  range_key = "sk"

  # Enable point-in-time recovery for disaster recovery
  point_in_time_recovery {
    enabled = true
  }

  # Enable server-side encryption with AWS managed key
  server_side_encryption {
    enabled = true
  }

  # TTL for automatic cleanup of old events
  ttl {
    enabled        = true
    attribute_name = "ttl"
  }

  # Primary key attributes
  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # Indexed attributes
  attribute {
    name = "eventName"
    type = "S"
  }

  attribute {
    name = "sourceType"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "sigmaRuleTitle"
    type = "S"
  }

  # GSI for correlation/event queries
  global_secondary_index {
    name            = "eventNameIndex"
    hash_key        = "eventName"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "sourceTypeIndex"
    hash_key        = "sourceType"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "sigmaRuleTitleIndex"
    hash_key        = "sigmaRuleTitle"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

}
