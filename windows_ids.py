import os
import win32evtlog
import win32event
import ollama
import json
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

# --- 1. CONFIGURATION ---
load_dotenv()
PINECONE_API_KEY = os.getenv('PINECONE_API_KEY')
INDEX_NAME = "security-knowledge"
OLLAMA_MODEL = "llama3.2:3b"

# --- 2. INITIALIZE COMPONENTS ---
print("Initializing Hybrid IDS Sensor...")

# Load Local Embedding Model
embed_model = SentenceTransformer('all-MiniLM-L6-v2')

# Connect to Cloud DB
pc = Pinecone(api_key=PINECONE_API_KEY)
if INDEX_NAME not in pc.list_indexes().names():
    print(f"Error: Index '{INDEX_NAME}' does not exist.")
    print("   Run 'seed_knowledge.py' first to create and populate the database.")
    exit()

index = pc.Index(INDEX_NAME)

# --- 3. CORE FUNCTIONS ---
def get_cloud_context(log_data):
    # Retrieves MITRE context from Pinecone Cloud.
    try:
        query_vec = embed_model.encode(log_data).tolist()
        results = index.query(vector=query_vec, top_k=1, include_metadata=True)
        
        # Threshold check: Only return if it's a good match (> 50% relevance)
        if results['matches'] and results['matches'][0]['score'] > 0.5:
            return results['matches'][0]['metadata']['text']
    except Exception as e:
        print(f"Cloud Query Error: {e}")
        
    return "No matching MITRE technique found in cloud knowledge base."

def process_event(event_id, event):
    # Hybrid Analysis: Pull context from Cloud, process locally with Ollama.
    log_data = " | ".join([str(s) for s in event.StringInserts])
    timestamp = event.TimeGenerated.Format('%Y-%m-%d %H:%M:%S')
    
    print(f"\n[ALERT] Event {event_id} at {timestamp}")

    # Step A: Get Context from Cloud (RAG)
    context = get_cloud_context(log_data)
    print(f"Cloud Context: {context[:100]}...")

    # Step B: Local AI Analysis
    prompt = (
        f"You are a Senior SOC Analyst. Evaluate this Windows Security Log.\n"
        f"LOG DATA: {log_data}\n\n"
        f"REFERENCE THREAT INTEL: {context}\n\n"
        "Instructions: Determine if the log represents an actual threat based on the reference. "
        "Categorize the risk as CLEAN, LOW, or CRITICAL. Cite the MITRE technique if applicable."
    )

    try:
        response = ollama.chat(model=OLLAMA_MODEL, messages=[{'role': 'user', 'content': prompt}])
        verdict = response['message']['content']
        print(f"AI Verdict:\n{verdict}\n" + "-"*50)
        
        with open("ids_alerts.json", "a") as f:
            f.write(json.dumps({"id": event_id, "time": timestamp, "analysis": verdict}) + "\n")
    except Exception as e:
        print(f"Inference Error: {e}")

# --- 4. REAL-TIME MONITORING ---
def run_ids():
    handle = win32evtlog.OpenEventLog(None, 'Security')
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    h_event = win32event.CreateEvent(None, 0, 0, None)
    win32evtlog.NotifyChangeEventLog(handle, h_event)

    print("Hybrid IDS is LIVE. Listening for Security Events...")

    while True:
        win32event.WaitForSingleObject(h_event, win32event.INFINITE)
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        for event in events:
            eid = event.EventID & 0xFFFF
            if eid in [4625, 4720, 5382]:
                process_event(eid, event)

if __name__ == "__main__":
    run_ids()