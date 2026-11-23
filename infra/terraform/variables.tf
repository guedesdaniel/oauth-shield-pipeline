variable "region" {
  description = "AWS region for every resource."
  type        = string
  default     = "us-east-2"
}

variable "alert_email" {
  description = "E-mail that receives the monthly budget alert."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Budget alert threshold in USD. The project should cost cents per month."
  type        = number
  default     = 5
}

variable "athena_scan_limit_bytes" {
  description = "Hard cap on data scanned per Athena query (cost guard). Default 1 GiB."
  type        = number
  default     = 1073741824
}
