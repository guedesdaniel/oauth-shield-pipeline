-- Run in the Athena console with workgroup "oauth-shield" and database "oauth_shield".
-- Partitions (dt) are UTC dates. Replace '2026-11-22' with the day you want; current_date can
-- already be "tomorrow" in UTC while it is still today in Brazil (after 21:00 BRT).

-- 1) High-risk client applications of a day, with the reasons that fired
SELECT client_id, risk_score, reasons
FROM risk_scores
WHERE dt = '2026-11-22' AND risk_level = 'HIGH'
ORDER BY risk_score DESC;

-- 2) Detection quality over time (synthetic ground truth)
SELECT dt, flagged, true_positives, false_positives, false_negatives, precision, recall
FROM detection_metrics
ORDER BY dt DESC
LIMIT 30;

-- 3) IPs attacking many client applications (credential stuffing / spraying)
SELECT dt, source_ip, country, distinct_clients, failed_requests, total_requests,
       ROUND(1.0 * failed_requests / total_requests, 2) AS fail_ratio
FROM ip_daily
WHERE distinct_clients >= 10
ORDER BY dt DESC, distinct_clients DESC;

-- 4) Success vs. error per client and day (the classic monitoring table)
SELECT dt, client_id, total_requests, success_count, error_count,
       ROUND(100.0 * error_count / total_requests, 2) AS error_pct
FROM client_daily
WHERE dt >= CAST(current_date - INTERVAL '7' DAY AS varchar)
ORDER BY error_pct DESC
LIMIT 50;

-- 5) Scope errors from a /24 the app does not usually use (learned from the previous 14 days)
SELECT d.dt, d.client_id, d.subnet, d.invalid_scope_count, d.success_count, d.total_requests
FROM client_subnet_daily d
LEFT JOIN client_subnet_baseline b
  ON b.dt = d.dt AND b.client_id = d.client_id AND b.subnet = d.subnet
WHERE d.dt = '2026-11-22'
  AND COALESCE(b.is_usual, false) = false
  AND d.invalid_scope_count >= 5
ORDER BY d.invalid_scope_count DESC;
