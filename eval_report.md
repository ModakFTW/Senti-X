# SENTINEL-X Evaluation Report

**Generated:** 2026-09-01 05:00 UTC  
**Scenario:** full  
**Overall Score:** 15.0%

---

## 1. Detection Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Precision | 0.0% | > 85% |
| Recall | 0.0% | > 80% |
| F1 Score | 0.0% | > 82% |
| False Positive Rate | 0.0% | < 5% |
| ROC-AUC | 0.0% | > 90% |
| TP / FP / FN / TN | 0/0/0/0 | |
| Total Events | 799 | |
| Flagged Events | 0 | |
| Actual Attack Events | 799 | |

---

## 2. Correlation Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Incident Grouping Accuracy | 0.0% | > 90% |
| Attack Chain Accuracy | 0.0% | > 80% |
| Adjusted Rand Index | 0.0000 | > 0.80 |
| Incidents Generated | 0 | |
| Incidents Expected | 6 | |
| Events Correctly Grouped | 0 | |

---

## 3. System Metrics

| Metric | Value |
|--------|-------|
| Events Processed | 10,299 |
| Suspicious Events | 799 |
| Correlated Events | 87 |
| Incidents Generated | 0 |
| Priority Incidents | 0 |
| Processing Time | 0.0 ms |
| Events / Second | 0 |
| Alert Compression Ratio | 0x |
| Priority Compression Ratio | 0x |

### Alert Compression Funnel

```
    10,299  Raw Events
           v  (1.0x reduction)
       799  Suspicious Events
           v  (12.9x reduction)
        87  Correlated Events
           v  (118.4x reduction)
         0  Incidents
           v  (0.0x reduction)
         0  Priority Incidents
```

---

## 4. RAG Quality Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Evidence Faithfulness | 100.0% | > 90% |
| MITRE Relevance | 100.0% | > 90% |
| Citation Coverage | 0.0% | > 90% |
| Incidents Processed | 0 of 0 | |

> **Note:** RAG pipeline has not run yet — these metrics are not meaningful.

---

## Overall Score: 15.0%

> Weighted average of Precision, Recall, F1, Incident Grouping Accuracy,
> Attack Chain Accuracy, Evidence Faithfulness, and MITRE Relevance.