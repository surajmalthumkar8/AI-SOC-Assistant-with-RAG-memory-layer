"""
Knowledge Store - Seed and manage organizational knowledge for RAG

Handles:
  - Seeding MITRE ATT&CK techniques from a local JSON file
  - Loading SOC playbooks from markdown files in knowledge/playbooks/
  - Bulk ingestion of past investigations from JSON
  - Initial bootstrap on first run
"""
import os
import json
import glob
from datetime import datetime
from typing import Dict, List, Any

from rag_engine import rag_engine, log


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge")
MITRE_SEED_FILE = os.path.join(KNOWLEDGE_DIR, "mitre_techniques.json")
PLAYBOOK_DIR = os.path.join(KNOWLEDGE_DIR, "playbooks")


# =========================================================================
# MITRE ATT&CK seeding
# =========================================================================

def seed_mitre_techniques(filepath: str = None) -> Dict:
    """Load MITRE ATT&CK techniques from JSON and store in RAG."""
    filepath = filepath or MITRE_SEED_FILE
    if not os.path.exists(filepath):
        log(f"MITRE seed file not found: {filepath}")
        return {"status": "skipped", "reason": "file_not_found", "path": filepath}

    with open(filepath, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    stored = 0
    for tech in techniques:
        result = rag_engine.store_mitre_technique(
            technique_id=tech["id"],
            name=tech["name"],
            description=tech.get("description", ""),
            tactic=tech.get("tactic", ""),
            platform=tech.get("platform", "Windows"),
            detection=tech.get("detection", ""),
            mitigation=tech.get("mitigation", ""),
        )
        if result.get("stored"):
            stored += 1

    log(f"Seeded {stored} MITRE techniques from {filepath}")
    return {"status": "success", "techniques_stored": stored, "source": filepath}


# =========================================================================
# Playbook loading
# =========================================================================

def load_playbooks(directory: str = None) -> Dict:
    """Load all .md playbook files from the playbooks directory."""
    directory = directory or PLAYBOOK_DIR
    if not os.path.isdir(directory):
        log(f"Playbook directory not found: {directory}")
        return {"status": "skipped", "reason": "dir_not_found", "path": directory}

    md_files = glob.glob(os.path.join(directory, "*.md"))
    if not md_files:
        log(f"No .md files found in {directory}")
        return {"status": "skipped", "reason": "no_files"}

    results = []
    for filepath in md_files:
        filename = os.path.basename(filepath)
        title = os.path.splitext(filename)[0].replace("_", " ").replace("-", " ").title()

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Derive category from filename
        category = "general"
        lower = filename.lower()
        if "powershell" in lower or "malware" in lower:
            category = "malware_response"
        elif "brute" in lower or "login" in lower or "auth" in lower:
            category = "account_security"
        elif "lateral" in lower or "movement" in lower:
            category = "lateral_movement"
        elif "exfil" in lower or "data" in lower:
            category = "data_protection"
        elif "phishing" in lower:
            category = "email_security"

        result = rag_engine.store_playbook(title, content, category)
        results.append({"file": filename, "title": title, "category": category, **result})

    log(f"Loaded {len(results)} playbooks from {directory}")
    return {"status": "success", "playbooks_loaded": len(results), "details": results}


# =========================================================================
# Bulk investigation ingestion
# =========================================================================

def ingest_investigations_from_file(filepath: str) -> Dict:
    """Load past investigations from a JSON file (list of reports)."""
    if not os.path.exists(filepath):
        return {"status": "error", "reason": "file_not_found", "path": filepath}

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Accept both a list and a dict-of-reports
    if isinstance(data, dict):
        reports = list(data.values())
    elif isinstance(data, list):
        reports = data
    else:
        return {"status": "error", "reason": "invalid_format"}

    stored = 0
    for report in reports:
        if isinstance(report, dict) and ("analysis" in report or "event_data" in report):
            result = rag_engine.store_investigation(report)
            if result.get("chunks_stored", 0) > 0:
                stored += 1

    log(f"Ingested {stored} investigations from {filepath}")
    return {"status": "success", "investigations_ingested": stored, "source": filepath}


# =========================================================================
# Full bootstrap
# =========================================================================

def bootstrap_knowledge() -> Dict:
    """
    Run on first startup to seed all knowledge sources.
    Safe to call multiple times - ChromaDB upsert is idempotent.
    """
    log("Bootstrapping RAG knowledge base...")
    results = {}

    # 1. MITRE techniques
    results["mitre"] = seed_mitre_techniques()

    # 2. Playbooks
    results["playbooks"] = load_playbooks()

    # 3. If demo_results.json exists, ingest past investigations
    demo_results_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "demo_results.json"
    )
    if os.path.exists(demo_results_path):
        results["demo_investigations"] = ingest_investigations_from_file(demo_results_path)
    else:
        results["demo_investigations"] = {"status": "skipped", "reason": "no_demo_results"}

    stats = rag_engine.get_stats()
    results["final_stats"] = stats
    log("Knowledge bootstrap complete", stats)
    return results
