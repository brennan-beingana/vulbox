#!/usr/bin/env python3
"""
End-to-end demo: create run → ingest Trivy/Falco/Atomic → correlate → remediate → report
"""
import json
import sys
import time

import requests

BASE_URL = "http://127.0.0.1:8000"


def print_header(text: str):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def demo():
    print_header("🚀 VulBox Security Assessment Demo")

    # Step 0: Health check
    print("0️⃣ Checking backend health...")
    try:
        health = requests.get(f"{BASE_URL}/health", timeout=2)
        if health.status_code != 200:
            print(f"   ❌ Backend not responding: {health.status_code}")
            sys.exit(1)
        print(f"   ✅ Backend OK\n")
    except Exception as e:
        print(f"   ❌ Cannot reach backend: {e}")
        print(f"   💡 Start the API with: uvicorn app.main:app --reload")
        sys.exit(1)

    # Step 1: Create a run
    print("1️⃣ Creating assessment run...")
    run_payload = {
        "project_name": "demo-app",
        "repo_url": "https://github.com/demo/app.git",
        "branch": "main",
        "commit_sha": "abc123def456",
        "image_name": "test-app",
        "image_tag": "latest",
    }
    run_resp = requests.post(f"{BASE_URL}/runs", json=run_payload)
    if run_resp.status_code != 200:
        print(f"   ❌ Failed to create run: {run_resp.text}")
        sys.exit(1)
    run = run_resp.json()
    run_id = run["id"]
    print(f"   ✅ Created run: ID={run_id}\n")

    # Step 2: Ingest Trivy findings
    print("2️⃣ Ingesting Trivy scan results...")
    with open("data/sample_outputs/trivy-fixture.json") as f:
        trivy_data = json.load(f)
    trivy_payload = {
        "results": trivy_data["Results"],
        "image_tag": "test-app:latest",
    }
    trivy_resp = requests.post(
        f"{BASE_URL}/runs/{run_id}/ingest/trivy", json=trivy_payload
    )
    if trivy_resp.status_code != 200:
        print(f"   ❌ Failed to ingest Trivy: {trivy_resp.text}")
        sys.exit(1)
    trivy_result = trivy_resp.json()
    print(f"   ✅ {trivy_result['message']}\n")

    # Step 3: Ingest Falco alerts
    print("3️⃣ Ingesting Falco runtime alerts...")
    with open("data/sample_outputs/falco-fixture.json") as f:
        falco_data = json.load(f)
    falco_resp = requests.post(
        f"{BASE_URL}/runs/{run_id}/ingest/falco", json=falco_data
    )
    if falco_resp.status_code != 200:
        print(f"   ❌ Failed to ingest Falco: {falco_resp.text}")
        sys.exit(1)
    falco_result = falco_resp.json()
    print(f"   ✅ {falco_result['message']}\n")

    # Step 4: Ingest Atomic results
    print("4️⃣ Ingesting Atomic validation results...")
    with open("data/sample_outputs/atomic-fixture.json") as f:
        atomic_data = json.load(f)
    atomic_resp = requests.post(
        f"{BASE_URL}/runs/{run_id}/ingest/atomic", json=atomic_data
    )
    if atomic_resp.status_code != 200:
        print(f"   ❌ Failed to ingest Atomic: {atomic_resp.text}")
        sys.exit(1)
    atomic_result = atomic_resp.json()
    print(f"   ✅ {atomic_result['message']}\n")

    # Step 5: Correlate findings
    print("5️⃣ Correlating findings across tools...")
    correlate_resp = requests.post(f"{BASE_URL}/runs/{run_id}/correlate")
    if correlate_resp.status_code != 200:
        print(f"   ❌ Failed to correlate: {correlate_resp.text}")
        sys.exit(1)
    correlate_result = correlate_resp.json()
    print(f"   ✅ {correlate_result['message']}\n")

    # Step 6: Generate remediation
    print("6️⃣ Generating remediation guidance...")
    remediate_resp = requests.post(f"{BASE_URL}/runs/{run_id}/remediate")
    if remediate_resp.status_code != 200:
        print(f"   ❌ Failed to remediate: {remediate_resp.text}")
        sys.exit(1)
    remediate_result = remediate_resp.json()
    print(f"   ✅ {remediate_result['message']}\n")

    # Step 7: Fetch final report
    print("7️⃣ Fetching final assessment report...")
    report_resp = requests.get(f"{BASE_URL}/reports/{run_id}")
    if report_resp.status_code != 200:
        print(f"   ❌ Failed to fetch report: {report_resp.text}")
        sys.exit(1)
    report = report_resp.json()
    print(f"   ✅ Report generated\n")

    # Step 8: Display summary
    print_header("📊 ASSESSMENT SUMMARY")
    print(f"Run ID:                    {report['run_id']}")
    print(f"Project:                   {report['project_name']}")
    print(f"Image:                     {report['image_tag']}")
    print(f"Status:                    {report['status']}")
    print(f"Total Findings:            {report['findings_count']}")
    print(f"Correlated Findings:       {report['correlated_findings_count']}")
    print(f"Remediation Actions:       {report['remediations_count']}")

    if report["correlated_findings_count"] > 0:
        print_header("🔴 CORRELATED FINDINGS")
        for i, finding in enumerate(report["correlated_findings"], 1):
            print(f"{i}. [{finding['confidence'].upper()}] {finding['finding_title']}")
            print(f"   Risk Score: {finding['risk_score']}/50")
            print(f"   Reason: {finding['correlation_reason']}")
            if finding["is_confirmed"]:
                print(f"   ✓ CONFIRMED by multiple tools")
            print()

    if report["remediations_count"] > 0:
        print_header("✅ REMEDIATION ACTIONS")
        for i, rem in enumerate(report["remediations"], 1):
            print(f"{i}. {rem['summary']}")
            print(f"   Action: {rem['priority_action']}")
            print(f"   Why: {rem['why_it_matters']}")
            print(f"   Example: {rem['example_fix']}")
            print(f"   Confidence: {rem['confidence'].upper()}")
            print()

    print_header("✨ DEMO COMPLETE")
    print(f"View full report via:")
    print(f"  curl http://127.0.0.1:8000/reports/{run_id} | jq .")
    print(f"\nAPI endpoints available:")
    print(f"  GET    /runs              - List all runs")
    print(f"  POST   /runs              - Create new run")
    print(f"  POST   /runs/{{id}}/ingest/trivy   - Ingest Trivy results")
    print(f"  POST   /runs/{{id}}/ingest/falco   - Ingest Falco alerts")
    print(f"  POST   /runs/{{id}}/ingest/atomic  - Ingest Atomic results")
    print(f"  POST   /runs/{{id}}/correlate     - Merge findings")
    print(f"  POST   /runs/{{id}}/remediate     - Generate recommendations")
    print(f"  GET    /reports/{{id}}            - Get final report")


if __name__ == "__main__":
    demo()
