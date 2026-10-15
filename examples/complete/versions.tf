terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

# In an AFT pipeline the provider block is generated at run time. It is
# declared here so that the example is self-contained. See
# docs/lessons-learned.md for the local override approach.
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
}
