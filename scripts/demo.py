#!/usr/bin/env python3
"""
End-to-end demo: register → create run (triggers orchestrator) → poll until COMPLETE → report.
Also demonstrates the dev-mode ingest path for fixture data.
"""
import json
import sys
import time

import requests

BASE_URL = "http://127.0.0.1:8000"
DEMO_EMAIL = "demo@vulbox.local"
DEMO_PASSWORD = "demo-password-123"


def print_header(text: str):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def get_token() -> str:
    """Register (if needed) and login, return JWT token."""
    # Try login first
    resp = requests.post(f"{BASE_URL}/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
    if resp.status_code == 200:
        return resp.json()["access_token"]

    # Register then login
    requests.post(f"{BASE_URL}/auth/register", json={
        "email": DEMO_EMAIL, "password": DEMO_PASSWORD, "role": "admin"
    })
    resp = requests.post(f"{BASE_URL}/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
    resp.raise_for_status()
    return resp.json()["access_token"]


def demo():
    print_header("VulBox Security Assessment Demo")

    # Step 0: Health check
    print("0. Checking backend health...")
    try:
        health = requests.get(f"{BASE_URL}/health", timeout=2)
        if health.status_code != 200:
            print(f"   Backend not responding: {health.status_code}")
            sys.exit(1)
        print(f"   Backend OK: {health.json()}\n")
    except Exception as e:
        print(f"   Cannot reach backend: {e}")
        print(f"   Start with: uvicorn app.main:app --reload")
        sys.exit(1)

    # Step 1: Auth
    print("1. Authenticating...")
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    print(f"   Authenticated\n")

    # Step 2: Create run (Orchestrator fires as BackgroundTask)
    print("2. Creating assessment run (Orchestrator will fire in background)...")
    run_payload = {
        "project_name": "demo-app",
        "repo_url": "https://github.com/demo/app.git",
        "branch": "main",
        "commit_sha": "abc123def456",
        "image_name": "test-app",
        "image_tag": "latest",
        "consent_granted": True,  # FR-01 requirement
    }
    run_resp = requests.post(f"{BASE_URL}/runs", json=run_payload, headers=headers)
    if run_resp.status_code != 200:
        print(f"   Failed to create run: {run_resp.text}")
        sys.exit(1)
    run = run_resp.json()
    run_id = run["id"]
    print(f"   Created run: ID={run_id}, status={run['status']}\n")

    # Step 3: Dev-mode ingest (optional — bypassed when Orchestrator runs in full mode)
    print("3. [Dev mode] Ingesting fixture data directly...")
    with open("data/sample_outputs/trivy-fixture.json") as f:
        trivy_data = json.load(f)
    trivy_resp = requests.post(
        f"{BASE_URL}/runs/{run_id}/ingest/trivy",
        json={"results": trivy_data["Results"], "image_tag": "test-app:latest"},
        headers=headers,
    )
    if trivy_resp.status_code == 200:
        print(f"   {trivy_resp.json()['message']}")

    with open("data/sample_outputs/falco-fixture.json") as f:
        falco_data = json.load(f)
    falco_resp = requests.post(f"{BASE_URL}/runs/{run_id}/ingest/falco", json=falco_data, headers=headers)
    if falco_resp.status_code == 200:
        print(f"   {falco_resp.json()['message']}")

    with open("data/sample_outputs/atomic-fixture.json") as f:
        atomic_data = json.load(f)
    atomic_resp = requests.post(f"{BASE_URL}/runs/{run_id}/ingest/atomic", json=atomic_data, headers=headers)
    if atomic_resp.status_code == 200:
        print(f"   {atomic_resp.json()['message']}\n")

    # Step 4: Poll until Orchestrator completes
    print("4. Polling until Orchestrator completes...")
    for i in range(60):
        status_resp = requests.get(f"{BASE_URL}/runs/{run_id}", headers=headers)
        current_status = status_resp.json().get("status", "UNKNOWN")
        print(f"   [{i+1}] Status: {current_status}")
        if current_status in ("COMPLETE", "FAILED"):
            break
        time.sleep(3)
    print()

    # Step 5: Fetch final report
    print("5. Fetching final assessment report...")
    report_resp = requests.get(f"{BASE_URL}/reports/{run_id}", headers=headers)
    if report_resp.status_code != 200:
        print(f"   Failed to fetch report: {report_resp.text}")
        sys.exit(1)
    report = report_resp.json()
    print(f"   Report generated\n")

    # Step 6: Display summary
    print_header("ASSESSMENT SUMMARY")
    print(f"Run ID:                {report['run_id']}")
    print(f"Project:               {report['project_name']}")
    print(f"Image:                 {report['image_tag']}")
    print(f"Status:                {report['status']}")
    print(f"Trivy Findings:        {report['trivy_findings_count']}")
    print(f"ART Tests Run:         {report['art_tests_count']}")
    print(f"Remediation Actions:   {report['remediations_count']}")

    if report["security_matrix"]:
        print_header("SECURITY MATRIX")
        print(f"{'MITRE Tactic':<20} {'Present':<10} {'Exploitable':<14} {'Detectable':<13} {'Risk'}")
        print("-" * 65)
        for e in report["security_matrix"]:
            print(
                f"{e['mitre_tactic_id']:<20} "
                f"{'Yes' if e['is_present'] else 'No':<10} "
                f"{'Yes' if e['is_exploitable'] else 'No':<14} "
                f"{'Yes' if e['is_detectable'] else 'No':<13} "
                f"{e['risk_score']}/50"
            )

    if report["remediations"]:
        print_header("REMEDIATION ACTIONS")
        for i, rem in enumerate(report["remediations"], 1):
            print(f"{i}. {rem['summary']}")
            print(f"   Action:     {rem['priority_action']}")
            print(f"   Why:        {rem['why_it_matters']}")
            print(f"   Confidence: {rem['confidence'].upper()}")
            print()

    print_header("DEMO COMPLETE")
    print(f"Full report:  GET  {BASE_URL}/reports/{run_id}")
    print(f"CSV export:   GET  {BASE_URL}/reports/{run_id}/export?format=csv")
    print(f"PDF export:   GET  {BASE_URL}/reports/{run_id}/export?format=pdf")
    print(f"Validations:  GET  {BASE_URL}/runs/{run_id}/validations")
    print(f"WebSocket:    WS   ws://127.0.0.1:8000/ws/runs/{{id}}/status")


if __name__ == "__main__":
    demo()
