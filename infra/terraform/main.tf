data "aws_caller_identity" "current" {}

locals {
  bucket_name = "oauth-shield-${data.aws_caller_identity.current.account_id}-${var.region}"

  # Glue tables over the Parquet output, discovered through partition projection
  # (no crawlers, no MSCK REPAIR: new dt= partitions are queryable immediately).
  tables = {
    oauth_events = {
      prefix = "bronze/oauth_events"
      columns = {
        event_id        = "string"
        event_ts        = "timestamp"
        client_id       = "string"
        source_ip       = "string"
        country         = "string"
        requested_scope = "string"
        status_code     = "bigint"
      }
    }
    client_daily = {
      prefix = "silver/client_daily"
      columns = {
        client_id                 = "string"
        total_requests            = "bigint"
        success_count             = "bigint"
        error_count               = "bigint"
        invalid_scope_count       = "bigint"
        invalid_client_count      = "bigint"
        distinct_ips              = "bigint"
        distinct_scopes_requested = "bigint"
        off_baseline_ip_requests  = "bigint"
        foreign_country_requests  = "bigint"
        expected_daily_volume     = "bigint"
      }
    }
    ip_daily = {
      prefix = "silver/ip_daily"
      columns = {
        source_ip        = "string"
        country          = "string"
        total_requests   = "bigint"
        failed_requests  = "bigint"
        distinct_clients = "bigint"
      }
    }
    risk_scores = {
      prefix = "gold/risk_scores"
      columns = {
        client_id         = "string"
        risk_score        = "bigint"
        risk_level        = "string"
        reasons           = "string"
        s_scope_probing   = "boolean"
        s_off_baseline_ip = "boolean"
        s_foreign_geo     = "boolean"
        s_volume_burst    = "boolean"
        s_suspicious_ip   = "boolean"
        # learned-baseline signal: scope errors from a /24 the app does not usually use
        s_new_subnet_scope_errors = "boolean"
      }
    }
    detection_metrics = {
      prefix = "gold/detection_metrics"
      columns = {
        run_date        = "string"
        flagged         = "bigint"
        true_positives  = "bigint"
        false_positives = "bigint"
        false_negatives = "bigint"
        precision       = "double"
        recall          = "double"
        baseline_ready  = "boolean"
      }
    }
    client_subnet_daily = {
      prefix = "silver/client_subnet_daily"
      columns = {
        client_id           = "string"
        subnet              = "string"
        total_requests      = "bigint"
        success_count       = "bigint"
        invalid_scope_count = "bigint"
        distinct_ips        = "bigint"
      }
    }
    client_subnet_baseline = {
      prefix = "silver/client_subnet_baseline"
      columns = {
        client_id             = "string"
        subnet                = "string"
        window_tokens         = "bigint"
        token_share           = "double"
        days_seen             = "bigint"
        is_usual              = "boolean"
        window_days_available = "bigint"
      }
    }
    # Evaluation-only tables: which apps were attacked, and which legitimately migrated.
    ground_truth = {
      prefix = "bronze/ground_truth"
      columns = {
        client_id   = "string"
        attack_type = "string"
      }
    }
    benign_events = {
      prefix = "bronze/benign_events"
      columns = {
        client_id  = "string"
        event_type = "string"
        subnet     = "string"
        notified   = "boolean"
      }
    }
  }
}

# ---------- Data lake bucket ----------
resource "aws_s3_bucket" "lake" {
  bucket        = local.bucket_name
  force_destroy = true # portfolio project: `terraform destroy` should leave nothing behind
}

resource "aws_s3_bucket_public_access_block" "lake" {
  bucket                  = aws_s3_bucket.lake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake" {
  bucket = aws_s3_bucket.lake.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "lake" {
  bucket = aws_s3_bucket.lake.id

  rule {
    id     = "expire-raw-events"
    status = "Enabled"
    filter {
      prefix = "bronze/"
    }
    expiration {
      days = 30
    }
  }

  rule {
    id     = "expire-athena-results"
    status = "Enabled"
    filter {
      prefix = "athena-results/"
    }
    expiration {
      days = 7
    }
  }
}

# ---------- Catalog + query engine ----------
resource "aws_glue_catalog_database" "this" {
  name = "oauth_shield"
}

resource "aws_glue_catalog_table" "tables" {
  for_each = local.tables

  name          = each.key
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification                = "parquet"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "2026-01-01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.lake.id}/${each.value.prefix}/dt=$${dt}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.id}/${each.value.prefix}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    dynamic "columns" {
      for_each = each.value.columns
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

resource "aws_athena_workgroup" "this" {
  name          = "oauth-shield"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration = true
    bytes_scanned_cutoff_per_query  = var.athena_scan_limit_bytes

    result_configuration {
      output_location = "s3://${aws_s3_bucket.lake.id}/athena-results/"
    }
  }
}

# ---------- Least-privilege identity for Airflow ----------
resource "aws_iam_user" "airflow" {
  name = "oauth-shield-airflow"
}

data "aws_iam_policy_document" "airflow" {
  statement {
    sid       = "ListBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.lake.arn]
  }
  statement {
    sid       = "ReadWriteLake"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.lake.arn}/bronze/*", "${aws_s3_bucket.lake.arn}/silver/*", "${aws_s3_bucket.lake.arn}/gold/*"]
  }
}

resource "aws_iam_user_policy" "airflow" {
  name   = "oauth-shield-lake-rw"
  user   = aws_iam_user.airflow.name
  policy = data.aws_iam_policy_document.airflow.json
}

# ---------- Cost guard ----------
resource "aws_budgets_budget" "monthly" {
  name         = "oauth-shield-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
