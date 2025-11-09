provider "aws" {
  region = var.region
}

provider "archive" {}
provider "null" {}
provider "random" {}