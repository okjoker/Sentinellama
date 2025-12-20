import os
import time
import requests
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from mitreattack.stix20 import MitreAttackData

# --- CONFIGURATION ---
load_dotenv()
PINECONE_API_KEY = os.getenv('PINECONE_API_KEY')
INDEX_NAME = "security-knowledge"

# --- INITIALIZATION ---
print("Initializing Knowledge Seeder...")
embed_model = SentenceTransformer('all-MiniLM-L6-v2')
pc = Pinecone(api_key=PINECONE_API_KEY)

# 1. Checks Pinecone Index
if INDEX_NAME not in pc.list_indexes().names():
    print(f"Index '{INDEX_NAME}' not found. Creating it now...")
    pc.create_index(
        name=INDEX_NAME,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
    print("Waiting for cloud resources to spin up...")
    time.sleep(20)

index = pc.Index(INDEX_NAME)

def expand_knowledge_base():
    # Downloads full MITRE ATT&CK data and populates Pinecone
    stats = index.describe_index_stats()
    print(f"Current Vector Count: {stats['total_vector_count']}")
    
    # Download Logic
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    local_file = "enterprise-attack.json"
    
    if not os.path.exists(local_file):
        print(f"Downloading MITRE dataset...")
        try:
            r = requests.get(mitre_url)
            with open(local_file, 'wb') as f:
                f.write(r.content)
            print("Download complete.")
        except Exception as e:
            print(f"Download failed: {e}")
            return

    # Ingestion Logic
    try:
        print("Parsing MITRE STIX Data (this may take a moment)...")
        mitre_data = MitreAttackData(local_file)
        techniques = mitre_data.get_techniques()
        
        print(f"Found {len(techniques)} techniques. Starting upload...")
        
        batch_size = 100
        for i in range(0, len(techniques), batch_size):
            batch = techniques[i:i + batch_size]
            vectors = []
            for tech in batch:
                ext_refs = tech.get('external_references', [])
                tech_id = ext_refs[0].get('external_id', tech.id) if ext_refs else tech.id
                
                name = tech.name
                desc = tech.get('description', 'No description available.')
                # Create a rich context string for the RAG
                content = f"Technique {tech_id}: {name}. {desc}"
                
                vec = embed_model.encode(content).tolist()
                vectors.append((tech_id, vec, {"text": content, "type": "MITRE_TECHNIQUE"}))
            
            index.upsert(vectors=vectors)
            print(f"Uploaded batch {i//batch_size + 1}")
            
        print("Knowledge Base Update Complete!")
            
    except Exception as e:
        print(f"Failed to expand knowledge base: {e}")

if __name__ == "__main__":
    expand_knowledge_base()