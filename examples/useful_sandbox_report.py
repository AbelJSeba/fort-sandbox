#!/usr/bin/env python3
"""
Useful sandbox workload that should pass under strict policies.

What it does:
- runs deterministic local analytics (no network)
- writes report artifacts under /app/output
- prints one JSON summary for machine parsing
"""

import json
import pathlib
import statistics
import time
from collections import defaultdict


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_sample_sales():
    return [
        {"day": "2026-01-01", "category": "compute", "amount": 120.0},
        {"day": "2026-01-02", "category": "storage", "amount": 45.5},
        {"day": "2026-01-03", "category": "network", "amount": 18.3},
        {"day": "2026-01-04", "category": "compute", "amount": 132.2},
        {"day": "2026-01-05", "category": "security", "amount": 27.0},
        {"day": "2026-01-06", "category": "storage", "amount": 40.1},
        {"day": "2026-01-07", "category": "compute", "amount": 141.8},
        {"day": "2026-01-08", "category": "network", "amount": 22.4},
    ]


def build_report(rows):
    by_category = defaultdict(float)
    amounts = []
    for row in rows:
        by_category[row["category"]] += row["amount"]
        amounts.append(row["amount"])

    total = round(sum(amounts), 2)
    avg = round(statistics.mean(amounts), 2)
    peak = round(max(amounts), 2)
    by_category_sorted = sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)

    recommendations = []
    top_name, top_value = by_category_sorted[0]
    if top_value > total * 0.5:
        recommendations.append(
            f"Top category '{top_name}' is above 50% of spend; consider rebalancing."
        )
    else:
        recommendations.append("Category distribution looks reasonably balanced.")
    if avg > 80:
        recommendations.append("Average daily amount is high; set anomaly alerts.")
    else:
        recommendations.append("Average daily amount is within baseline.")

    return {
        "generated_at": now_iso(),
        "row_count": len(rows),
        "total_amount": total,
        "average_amount": avg,
        "peak_amount": peak,
        "category_totals": [
            {"category": name, "amount": round(value, 2)} for name, value in by_category_sorted
        ],
        "recommendations": recommendations,
    }


def write_artifacts(report):
    lines = [
        "Useful Sandbox Report",
        f"generated_at: {report['generated_at']}",
        f"row_count: {report['row_count']}",
        f"total_amount: {report['total_amount']}",
        f"average_amount: {report['average_amount']}",
        f"peak_amount: {report['peak_amount']}",
        "category_totals:",
    ]
    lines.extend(
        [f"- {row['category']}: {row['amount']}" for row in report["category_totals"]]
    )
    lines.append("recommendations:")
    lines.extend([f"- {r}" for r in report["recommendations"]])

    candidates = [
        pathlib.Path("/app/output"),       # preferred for Fort artifact capture
        pathlib.Path("/tmp/fort-output"),  # fallback for local runs
    ]

    last_error = None
    for out_dir in candidates:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            json_path = out_dir / "useful_report.json"
            txt_path = out_dir / "useful_report.txt"
            json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return [str(json_path), str(txt_path)]
        except Exception as exc:  # noqa: BLE001
            last_error = exc

    raise RuntimeError(f"failed to write artifacts to all candidate paths: {last_error}")


def main():
    rows = load_sample_sales()
    report = build_report(rows)

    events = []
    try:
        files = write_artifacts(report)
        events.append({"event": "artifact_write", "ok": True, "detail": ", ".join(files)})
    except Exception as exc:  # noqa: BLE001
        events.append({"event": "artifact_write", "ok": False, "detail": str(exc)})

    result = {
        "example": "useful_sandbox_report",
        "timestamp": now_iso(),
        "ok": all(event["ok"] for event in events),
        "events": events,
        "summary": {
            "total_amount": report["total_amount"],
            "top_category": report["category_totals"][0]["category"],
            "recommendation_count": len(report["recommendations"]),
        },
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
