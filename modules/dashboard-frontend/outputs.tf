output "cloudfront_distribution_domain" {
  description = "CloudFront distribution domain name (the dashboard URL)"
  value       = aws_cloudfront_distribution.dashboard.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.dashboard.id
}

output "dashboard_url" {
  description = "Full URL to access the dashboard"
  value       = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
}
