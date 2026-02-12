"""
RAG Engine - Retrieval-Augmented Generation for SOC AI Investigations

Local vector database using ChromaDB for organizational knowledge.
Stores and retrieves past investigations, analyst feedback, SOC playbooks,
and MITRE ATT&CK knowledge to augment LLM analysis with org-specific context.

Collections:
  - investigations  : Completed investigation reports and outcomes
  - analyst_feedback : Analyst verdicts, overrides, and notes
  - playbooks       : SOC playbooks and response procedures
  - mitre_knowledge  : MITRE ATT&CK techniques, tactics, mitigations
"""
import os
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional

import chromadb
from chromadb.config import Settings


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RAG_DATA_DIR = os.getenv(
    "RAG_DATA_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "rag_data"),
)
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))
RAG_ENABLED = os.getenv("RAG_ENABLED", "true").lower() == "true"


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [RAG-ENGINE] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:500]}")


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------

def _chunk_text(text: str, max_chars: int = 1500, overlap: int = 200) -> List[str]:
    """Split long text into overlapping chunks for embedding."""
    if len(text) <= max_chars:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = start + max_chars
        chunk = text[start:end]
        # Break at sentence / paragraph boundary when possible
        if end < len(text):
            last_period = chunk.rfind(". ")
            last_newline = chunk.rfind("\n")
            break_at = max(last_period, last_newline)
            if break_at > max_chars // 2:
                chunk = chunk[: break_at + 1]
                end = start + break_at + 1
        chunks.append(chunk.strip())
        start = end - overlap
    return [c for c in chunks if c]


# =========================================================================
# RAGEngine
# =========================================================================

class RAGEngine:
    """
    Local RAG engine backed by ChromaDB (persistent, on-disk).

    Public API
    ----------
    store_investigation(report)      -> Dict
    store_feedback(...)              -> Dict
    store_playbook(title, content)   -> Dict
    store_mitre_technique(...)       -> Dict
    retrieve_context(event_data)     -> Dict   (the main retrieval call)
    search(query, collection, top_k) -> Dict
    get_stats()                      -> Dict
    """

    def __init__(self, persist_dir: str = None):
        self.persist_dir = persist_dir or RAG_DATA_DIR
        self.enabled = RAG_ENABLED
        if not self.enabled:
            log("RAG engine DISABLED via RAG_ENABLED=false")
            return

        os.makedirs(self.persist_dir, exist_ok=True)
        log("Initializing RAG engine", {"persist_dir": self.persist_dir})

        self.client = chromadb.PersistentClient(
            path=self.persist_dir,
            settings=Settings(anonymized_telemetry=False),
        )
        self._init_collections()
        log("RAG engine ready", self.get_stats())

    # ------------------------------------------------------------------
    # Collection setup
    # ------------------------------------------------------------------

    def _init_collections(self):
        common_meta = {"hnsw:space": "cosine"}

        self.investigations = self.client.get_or_create_collection(
            name="investigations",
            metadata={**common_meta, "description": "Past SOC investigations"},
        )
        self.feedback = self.client.get_or_create_collection(
            name="analyst_feedback",
            metadata={**common_meta, "description": "Analyst verdicts and overrides"},
        )
        self.playbooks = self.client.get_or_create_collection(
            name="playbooks",
            metadata={**common_meta, "description": "SOC playbooks and procedures"},
        )
        self.mitre = self.client.get_or_create_collection(
            name="mitre_knowledge",
            metadata={**common_meta, "description": "MITRE ATT&CK techniques"},
        )

    # ==================================================================
    # STORAGE
    # ==================================================================

    def store_investigation(self, report: Dict) -> Dict:
        """Persist a completed investigation for future RAG retrieval."""
        if not self.enabled:
            return {"stored": False, "reason": "rag_disabled"}

        inv_id = report.get(
            "investigation_id",
            f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        )
        event_data = report.get("event_data", {})
        analysis = report.get("analysis", {})

        doc_text = self._investigation_to_text(report)
        chunks = _chunk_text(doc_text)

        meta_base = {
            "investigation_id": str(inv_id),
            "classification": str(analysis.get("classification", "unknown")),
            "severity": str(analysis.get("severity", "unknown")),
            "event_type": str(event_data.get("event_type", "unknown")),
            "host": str(event_data.get("host", "")),
            "user": str(event_data.get("user", "")),
            "timestamp": report.get("timestamp", datetime.now().isoformat()),
            "source": "auto_ingest",
        }

        ids: List[str] = []
        for i, chunk in enumerate(chunks):
            doc_id = f"inv-{inv_id}-{i}"
            meta = {**meta_base, "chunk_index": i, "total_chunks": len(chunks)}
            self.investigations.upsert(
                ids=[doc_id], documents=[chunk], metadatas=[meta]
            )
            ids.append(doc_id)

        log(f"Stored investigation {inv_id}", {"chunks": len(chunks)})
        return {"investigation_id": inv_id, "chunks_stored": len(chunks), "doc_ids": ids}

    def store_feedback(
        self,
        investigation_id: str,
        analyst_verdict: str,
        analyst_notes: str = "",
        original_classification: str = "",
        correct_severity: str = "",
    ) -> Dict:
        """Store analyst feedback / override for a past investigation."""
        if not self.enabled:
            return {"stored": False, "reason": "rag_disabled"}

        ts = datetime.now().isoformat()
        is_override = (
            bool(original_classification)
            and analyst_verdict != original_classification
        )

        doc_text = (
            f"Analyst feedback for investigation {investigation_id}. "
            f"Analyst verdict: {analyst_verdict}. "
        )
        if original_classification:
            doc_text += f"AI originally classified as: {original_classification}. "
        if is_override:
            doc_text += "This was an AI OVERRIDE - the analyst disagreed with the AI classification. "
        if correct_severity:
            doc_text += f"Correct severity: {correct_severity}. "
        if analyst_notes:
            doc_text += f"Analyst notes: {analyst_notes}"

        doc_id = f"fb-{investigation_id}-{hashlib.sha256(ts.encode()).hexdigest()[:8]}"

        self.feedback.upsert(
            ids=[doc_id],
            documents=[doc_text],
            metadatas=[{
                "investigation_id": investigation_id,
                "analyst_verdict": analyst_verdict,
                "original_classification": original_classification,
                "correct_severity": correct_severity,
                "is_override": str(is_override),
                "timestamp": ts,
            }],
        )
        log(f"Stored feedback for {investigation_id}", {"verdict": analyst_verdict, "override": is_override})
        return {"doc_id": doc_id, "stored": True, "is_override": is_override}

    def store_playbook(
        self, title: str, content: str, category: str = "general"
    ) -> Dict:
        """Store a SOC playbook / procedure document."""
        if not self.enabled:
            return {"stored": False, "reason": "rag_disabled"}

        chunks = _chunk_text(content)
        slug = title.lower().replace(" ", "_")[:30]

        ids: List[str] = []
        for i, chunk in enumerate(chunks):
            doc_id = f"pb-{slug}-{i}"
            self.playbooks.upsert(
                ids=[doc_id],
                documents=[chunk],
                metadatas=[{
                    "title": title,
                    "category": category,
                    "chunk_index": i,
                    "total_chunks": len(chunks),
                    "timestamp": datetime.now().isoformat(),
                }],
            )
            ids.append(doc_id)

        log(f"Stored playbook: {title}", {"chunks": len(chunks)})
        return {"title": title, "chunks_stored": len(chunks), "doc_ids": ids}

    def store_mitre_technique(
        self,
        technique_id: str,
        name: str,
        description: str,
        tactic: str,
        platform: str = "Windows",
        detection: str = "",
        mitigation: str = "",
    ) -> Dict:
        """Store a single MITRE ATT&CK technique."""
        if not self.enabled:
            return {"stored": False, "reason": "rag_disabled"}

        doc_text = (
            f"{technique_id} - {name}. "
            f"Tactic: {tactic}. Platform: {platform}. "
            f"Description: {description}"
        )
        if detection:
            doc_text += f" Detection: {detection}"
        if mitigation:
            doc_text += f" Mitigation: {mitigation}"

        doc_id = f"mitre-{technique_id}"
        self.mitre.upsert(
            ids=[doc_id],
            documents=[doc_text],
            metadatas=[{
                "technique_id": technique_id,
                "name": name,
                "tactic": tactic,
                "platform": platform,
                "timestamp": datetime.now().isoformat(),
            }],
        )
        return {"technique_id": technique_id, "stored": True}

    # ==================================================================
    # RETRIEVAL  (the core RAG call)
    # ==================================================================

    def retrieve_context(self, event_data: Dict, top_k: int = None) -> Dict:
        """
        Retrieve relevant organizational context for a security event.
        Searches all four collections and returns a combined context block
        suitable for injection into the LLM prompt.
        """
        if not self.enabled:
            return {"rag_active": False, "reason": "rag_disabled"}

        top_k = top_k or RAG_TOP_K
        query_text = self._event_to_query(event_data)
        log(f"RAG retrieval for: {query_text[:100]}...")

        context: Dict[str, Any] = {
            "similar_investigations": [],
            "analyst_feedback": [],
            "relevant_playbooks": [],
            "mitre_context": [],
            "query_used": query_text,
            "rag_active": True,
        }

        # Search each collection (only if it has documents)
        if self.investigations.count() > 0:
            res = self.investigations.query(
                query_texts=[query_text],
                n_results=min(top_k, self.investigations.count()),
            )
            context["similar_investigations"] = self._format_results(res)

        if self.feedback.count() > 0:
            res = self.feedback.query(
                query_texts=[query_text],
                n_results=min(top_k, self.feedback.count()),
            )
            context["analyst_feedback"] = self._format_results(res)

        if self.playbooks.count() > 0:
            res = self.playbooks.query(
                query_texts=[query_text],
                n_results=min(top_k, self.playbooks.count()),
            )
            context["relevant_playbooks"] = self._format_results(res)

        if self.mitre.count() > 0:
            res = self.mitre.query(
                query_texts=[query_text],
                n_results=min(top_k, self.mitre.count()),
            )
            context["mitre_context"] = self._format_results(res)

        context["total_results"] = sum(
            len(v) for v in context.values() if isinstance(v, list)
        )

        log("RAG retrieval complete", {
            "investigations": len(context["similar_investigations"]),
            "feedback": len(context["analyst_feedback"]),
            "playbooks": len(context["relevant_playbooks"]),
            "mitre": len(context["mitre_context"]),
        })
        return context

    def search(self, query: str, collection: str = "all", top_k: int = 5) -> Dict:
        """Direct semantic search across one or all collections."""
        if not self.enabled:
            return {"rag_active": False, "reason": "rag_disabled"}

        collections_map = {
            "investigations": self.investigations,
            "analyst_feedback": self.feedback,
            "playbooks": self.playbooks,
            "mitre_knowledge": self.mitre,
        }

        if collection == "all":
            targets = collections_map
        elif collection in collections_map:
            targets = {collection: collections_map[collection]}
        else:
            return {"error": f"Unknown collection: {collection}"}

        results: Dict[str, Any] = {}
        for name, coll in targets.items():
            if coll.count() > 0:
                res = coll.query(
                    query_texts=[query],
                    n_results=min(top_k, coll.count()),
                )
                results[name] = self._format_results(res)

        return {"query": query, "results": results}

    # ==================================================================
    # STATUS / STATS
    # ==================================================================

    def get_stats(self) -> Dict:
        if not self.enabled:
            return {"status": "disabled"}
        return {
            "status": "active",
            "persist_dir": self.persist_dir,
            "collections": {
                "investigations": self.investigations.count(),
                "analyst_feedback": self.feedback.count(),
                "playbooks": self.playbooks.count(),
                "mitre_knowledge": self.mitre.count(),
            },
            "total_documents": (
                self.investigations.count()
                + self.feedback.count()
                + self.playbooks.count()
                + self.mitre.count()
            ),
        }

    # ==================================================================
    # INTERNAL HELPERS
    # ==================================================================

    def _event_to_query(self, event_data: Dict) -> str:
        """Convert event data into a natural-language search query."""
        parts: List[str] = []
        mappings = [
            ("event_type", "event type"),
            ("process", "process"),
            ("host", "host"),
            ("user", "user"),
            ("src_ip", "source IP"),
            ("dest_ip", "destination IP"),
            ("method", "method"),
        ]
        for field, label in mappings:
            val = event_data.get(field, "")
            if val:
                parts.append(f"{label}: {val}")

        cmd = event_data.get("command_line", "")
        if cmd:
            parts.append(f"command: {cmd[:200]}")

        if not parts:
            parts.append(json.dumps(event_data, default=str)[:300])

        return ". ".join(parts)

    def _investigation_to_text(self, report: Dict) -> str:
        """Flatten an investigation report into searchable prose."""
        ev = report.get("event_data", {})
        an = report.get("analysis", {})

        parts = [
            f"Investigation {report.get('investigation_id', 'unknown')}.",
            f"Event type: {ev.get('event_type', 'unknown')}.",
            f"Host: {ev.get('host', 'unknown')}. User: {ev.get('user', 'unknown')}.",
        ]

        cmd = ev.get("command_line", "")
        if cmd:
            parts.append(f"Command: {cmd[:300]}.")
        src = ev.get("src_ip", "")
        if src:
            parts.append(f"Source IP: {src}.")

        parts.append(f"Classification: {an.get('classification', 'unknown')}.")
        parts.append(f"Severity: {an.get('severity', 'unknown')}.")
        parts.append(f"Confidence: {an.get('confidence', 'unknown')}%.")

        # MITRE techniques
        techniques = an.get("mitre_attack", {}).get("techniques", [])
        if techniques:
            tech_strs = []
            for t in techniques:
                if isinstance(t, dict):
                    tech_strs.append(f"{t.get('id', '')} {t.get('name', '')}")
                else:
                    tech_strs.append(str(t))
            parts.append(f"MITRE techniques: {', '.join(tech_strs)}.")

        summary = an.get("analyst_summary", "")
        if summary:
            parts.append(f"Summary: {summary}")

        # Recommended actions
        actions = an.get("recommended_actions", {})
        if isinstance(actions, dict):
            immediate = actions.get("immediate", [])
            if immediate:
                strs = [
                    a.get("action", "") if isinstance(a, dict) else str(a)
                    for a in immediate
                ]
                parts.append(f"Immediate actions: {'; '.join(strs)}")

        return " ".join(parts)

    @staticmethod
    def _format_results(raw: Dict) -> List[Dict]:
        """Convert ChromaDB query output to clean list of dicts."""
        if not raw or not raw.get("documents"):
            return []

        docs = raw["documents"][0] if raw["documents"] else []
        metas = raw["metadatas"][0] if raw.get("metadatas") else []
        dists = raw["distances"][0] if raw.get("distances") else []
        ids = raw["ids"][0] if raw.get("ids") else []

        formatted: List[Dict] = []
        for i in range(len(docs)):
            # Cosine distance in [0, 2]; convert to similarity in [0, 1]
            similarity = round(1.0 - (dists[i] / 2.0), 3) if i < len(dists) else 0
            formatted.append({
                "id": ids[i] if i < len(ids) else None,
                "content": docs[i],
                "relevance_score": similarity,
                "metadata": metas[i] if i < len(metas) else {},
            })
        return formatted


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
try:
    rag_engine = RAGEngine()
except Exception as e:
    log(f"RAG engine initialization failed: {e} - running without RAG")

    class _DisabledRAG:
        enabled = False
        def retrieve_context(self, *a, **kw):
            return {"rag_active": False, "reason": "init_failed", "error": str(e)}
        def store_investigation(self, *a, **kw):
            return {"stored": False}
        def store_feedback(self, *a, **kw):
            return {"stored": False}
        def store_playbook(self, *a, **kw):
            return {"stored": False}
        def store_mitre_technique(self, *a, **kw):
            return {"stored": False}
        def search(self, *a, **kw):
            return {"rag_active": False}
        def get_stats(self):
            return {"status": "init_failed", "error": str(e)}

    rag_engine = _DisabledRAG()
