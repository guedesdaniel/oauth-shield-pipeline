-- Run in the Athena console with workgroup "oauth-shield" and database "oauth_shield".

-- 1) Today's high-risk client applications, with the reasons that fired
SELECT client_id, risk_score, reasons
FROM risk_scores
WHERE dt = CAST(current_date AS varchar) AND risk_level = 'HIGH'
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
