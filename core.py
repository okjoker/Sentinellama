"""
Shared analysis core for Sentinellama.

Holds the RAG + Ollama logic so both the CLI sensor (windows_ids.py) and the
web app (app.py) use the exact same brain. Heavy models are loaded lazily so
importing this module is cheap.
"""
import os
import re
import json
import threading
from datetime import datetime

from dotenv import load_dotenv

# --- CONFIGURATION ---
load_dotenv()
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
INDEX_NAME = os.getenv("PINECONE_INDEX", "security-knowledge")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
# all-MiniLM-L6-v2 cosine scores run low against long MITRE descriptions:
# correct technique matches land ~0.41-0.45 while benign logs top out ~0.40,
# so 0.5 silently discarded good retrievals.
RELEVANCE_THRESHOLD = 0.4
ALERTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ids_alerts.json")

# --- LAZY-LOADED COMPONENTS ---
_lock = threading.Lock()
_embed_model = None
_index = None


def get_embed_model():
    """Load the local embedding model once, on first use."""
    global _embed_model
    if _embed_model is None:
        with _lock:
            if _embed_model is None:
                from sentence_transformers import SentenceTransformer
                _embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embed_model


def get_index():
    """Connect to the Pinecone index once, on first use."""
    global _index
    if _index is None:
        with _lock:
            if _index is None:
                from pinecone import Pinecone
                pc = Pinecone(api_key=PINECONE_API_KEY)
                if INDEX_NAME not in pc.list_indexes().names():
                    raise RuntimeError(
                        f"Pinecone index '{INDEX_NAME}' not found. "
                        "Run seed_knowledge.py first to create and populate it."
                    )
                _index = pc.Index(INDEX_NAME)
    return _index


# --- CORE FUNCTIONS ---
def parse_risk(verdict):
    """Pull a coarse risk level out of the model's free-text verdict.

    The model is told to end with "FINAL VERDICT: <LEVEL>", so that line wins.
    For older/looser outputs, fall back to verdict-shaped phrases, always
    taking the LAST occurrence: with chain-of-thought output the conclusion
    comes at the end, and the reasoning body may name other levels while
    weighing them ("not a CRITICAL attack ... risk as LOW").
    """
    upper = (verdict or "").upper()
    levels = "CRITICAL|HIGH|MEDIUM|LOW|CLEAN"
    patterns = (
        rf"FINAL VERDICT[:\s\*\[]*({levels})\b",
        rf"RISK[^.\n]{{0,25}}?\b({levels})\b",  # "risk as LOW", "risk: CRITICAL"
        rf"\*\*({levels})\*\*",                 # bolded verdict
        rf"\b({levels})\b",                     # fallback: last level mentioned
    )
    for pat in patterns:
        matches = re.findall(pat, upper)
        if matches:
            return matches[-1]
    return "UNKNOWN"


def get_cloud_context(log_data, top_k=3):
    """Retrieve relevant MITRE techniques from Pinecone (RAG).

    Returns "" when nothing clears the relevance threshold - deliberately NOT
    a "no match found" sentence, because feeding that to the model as threat
    intel biases it toward calling everything benign.
    """
    try:
        query_vec = get_embed_model().encode(log_data).tolist()
        results = get_index().query(vector=query_vec, top_k=top_k, include_metadata=True)
        hits = [m["metadata"]["text"] for m in results["matches"]
                if m["score"] > RELEVANCE_THRESHOLD]
        return "\n---\n".join(hits)
    except Exception as e:
        return f"Cloud query error: {e}"


def search_knowledge(query, top_k=5):
    """Semantic search over the MITRE knowledge base."""
    query_vec = get_embed_model().encode(query).tolist()
    results = get_index().query(vector=query_vec, top_k=top_k, include_metadata=True)
    return [
        {
            "id": m["id"],
            "score": round(float(m["score"]), 4),
            "text": m["metadata"].get("text", ""),
        }
        for m in results["matches"]
    ]


def analyze_log(log_data, event_id=None, timestamp=None, persist=True,
                source=None, etype=None, query_text=None):
    """Hybrid analysis: cloud RAG context + local Ollama SOC-analyst verdict.

    query_text, when given, is used for the vector search instead of log_data:
    embedding the "[Application log] Source: ... | Type: ..." preamble dilutes
    semantic similarity and retrieves the wrong techniques.
    """
    import ollama

    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    context = get_cloud_context(query_text or log_data)
    context_block = context or (
        "(no strong semantic match in the knowledge base - this is absence of "
        "enrichment, NOT evidence that the event is benign)"
    )
    log_kind = f"Windows {source} Log" if source else "Windows Event Log"
    prompt = (
    f"You are a Senior SOC Analyst evaluating a Windows log entry.\n\n"
    f"=== TARGET LOG TO ANALYZE ===\n"
    f"<log_kind>{log_kind}</log_kind>\n"
    f"<log_data>{log_data}</log_data>\n"
    f"=============================\n\n"
    f"=== ENRICHMENT THREAT INTEL (MITRE ATT&CK Matches) ===\n"
    f"{context_block if context_block else 'No threat intel provided.'}\n"
    f"====================================================\n\n"
    f"Analyze the log step-by-step using the following strict structure:\n\n"
    f"1. OBSERVATIONS:\n"
    f"List only concrete artifacts literally present inside the <log_data> tags (file paths, executable names, accounts, network addresses, and behavior). \n"
    f"STRICT RULE: If a file path is not explicitly written inside the <log_data> tags, write 'Path: Not provided'—do not assume or invent one.\n\n"
    f"2. HEURISTICS:\n"
    f"Evaluate the explicit items from your observations against known risk patterns. \n"
    f"- Treat standard exception codes (like 0xc0000005) or update failures as CLEAN application noise unless they are tied to an explicitly malicious command line or untrusted path.\n"
    f"- Flag suspicious locations, malware naming conventions, or rapid failures *only* if they appear in your observations.\n"
    f"STRICT RULE: Every indicator you flag must quote the exact string from <log_data> that triggered it. If you cannot quote it verbatim, DO NOT flag it.\n\n"
    f"3. THREAT INTEL:\n"
    f"Provide matching MITRE technique IDs only if the behavior in <log_data> directly maps to them. A lack of a threat intel match does NOT mean the event is benign; never lower a heuristic risk rating due to a missing intelligence match.\n\n"
    f"4. VERDICT SUMMARY:\n"
    f"Weigh the observations and heuristics against the threat intel. Heuristic indicators override a lack of threat intel.\n\n"
    f"=== CRITICAL CONSTRAINT ===\n"
    f"Never reference, output, or invent paths like 'C:\\Users\\Public' or 'AppData\\Local\\Temp' unless those exact strings are explicitly contained inside the <log_data> tags above.\n\n"
    f"End your response with exactly one line in this format:\n"
    f"FINAL VERDICT: [CLEAN, LOW, MEDIUM, HIGH, or CRITICAL]"
)

    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0.2},
    )
    verdict = response["message"]["content"]

    alert = {
        "id": event_id,
        "time": timestamp,
        "log": log_data,
        "context": context,
        "source": source,
        "etype": etype,
        "risk": parse_risk(verdict),
        "analysis": verdict,
    }
    if persist:
        append_alert(alert)
    return alert


# --- PERSISTENCE ---
def append_alert(alert):
    """Append one alert as a JSON line to the alerts log."""
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")


def load_alerts(limit=200):
    """Read recent alerts back from disk, tolerating the older record format."""
    if not os.path.exists(ALERTS_FILE):
        return []
    alerts = []
    with open(ALERTS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Backfill fields for alerts written before the web GUI existed.
            alert.setdefault("risk", parse_risk(alert.get("analysis", "")))
            alert.setdefault("log", "")
            alert.setdefault("context", "")
            alerts.append(alert)
    return alerts[-limit:]
