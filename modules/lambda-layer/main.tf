resource "null_resource" "build_trailalerts_lambda_layer" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      chmod +x ${local.rel_path_root}/scripts/lambda-layer/build.sh
      ${local.rel_path_root}/scripts/lambda-layer/build.sh
    EOT
  }
}

resource "aws_lambda_layer_version" "trailalerts_detection_layer" {
  depends_on          = [null_resource.build_trailalerts_lambda_layer]
  layer_name          = local.layer_name
  compatible_runtimes = ["python3.13"]
  skip_destroy        = true
  filename            = "${local.rel_path_root}/build/layer.zip"
  source_code_hash    = filebase64sha256("${local.rel_path_root}/build/layer.zip")

  description = "Layer containing TrailAlerts detection dependencies"
}