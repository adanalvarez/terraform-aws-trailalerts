locals {
  module_name   = basename(path.module)
  rel_path_root = trimsuffix(path.module, "modules/${local.module_name}") != "" ? trimsuffix(path.module, "modules/${local.module_name}") : "."
  event_processor_secret_arns = distinct(compact([
    var.vpnapi_key_secret_arn,
    var.webhook_url_secret_arn,
    var.webhook_headers_secret_arn,
  ]))
}