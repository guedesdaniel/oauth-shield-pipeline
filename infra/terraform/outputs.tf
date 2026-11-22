output "bucket_name" {
  description = "Put this in S3_BUCKET in your .env."
  value       = aws_s3_bucket.lake.id
}

output "athena_workgroup" {
  value = aws_athena_workgroup.this.name
}

output "glue_database" {
  value = aws_glue_catalog_database.this.name
}

output "airflow_iam_user" {
  description = "Create an access key for this user in the IAM console and put it in .env."
  value       = aws_iam_user.airflow.name
}
