data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "trailalerts_rules_bucket" {
  bucket = lower("${var.project}-rules-${data.aws_caller_identity.current.account_id}")
}

resource "aws_s3_object" "sigma_rules_folder" {
  bucket = aws_s3_bucket.trailalerts_rules_bucket.id
  key    = "sigma_rules/"
  source = "/dev/null"
}

resource "aws_s3_object" "postprocessing_rules_folder" {
  bucket = aws_s3_bucket.trailalerts_rules_bucket.id
  key    = "postprocessing_rules/"
  source = "/dev/null"
}