# rag.py
import os
import json
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from time import time
import faiss

# Vertex / embedding client
try:
    from google import genai
    GENAI_AVAILABLE = True
except Exception:
    GENAI_AVAILABLE = False

# fallback to requests for embedding API if needed
import requests

# Config from env
EMBED_MODEL = os.environ.get("EMBED_MODEL", "textembedding-gecko-001")  # Vertex embedding model or change
PROJECT =  os.environ.get("GCP_PROJECT") or os.environ.get("PROJECT_ID") or "angular-sorter-473216-k8"
LOCATION = os.environ.get("GCP_LOCATION", "global")

INDEX_DIR = Path(os.environ.get("FAISS_DIR", "faiss_index"))
INDEX_DIR.mkdir(parents=True, exist_ok=True)
METADATA_FILE = INDEX_DIR / "metadata.json"
INDEX_FILE = INDEX_DIR / "index.faiss"
DIM = int(os.environ.get("EMBED_DIM", 1536))  # set according to embedding model; adjust if different

# ---------- Embedding functions ----------
def embed_texts_vertex(texts: List[str]) -> List[List[float]]:
    """
    Use Vertex embeddings via google-genai. Return list of vectors.
    """
    if not GENAI_AVAILABLE:
        raise RuntimeError("Vertex genai SDK not available")
    client = genai.Client() if hasattr(genai, "Client") else None
    # This sample uses genai.Client().embeddings.create or genai.embedding.create depending on SDK
    # Try common patterns
    out = []
    if client and hasattr(client, "embeddings"):
        for t in texts:
            resp = client.embeddings.create(model=EMBED_MODEL, input=t)
            # resp.data[0].embedding or resp.embedding depending on response
            vec = None
            try:
                vec = resp.data[0].embedding
            except Exception:
                vec = getattr(resp, "embedding", None)
            if vec is None:
                raise RuntimeError("Unexpected embedding response: " + str(resp))
            out.append(vec)
    else:
        # fallback to top-level
        resp = genai.embeddings.create(model=EMBED_MODEL, input=texts)
        for r in resp.data:
            out.append(r.embedding)
    return out

def embed_texts_openai(texts: List[str]) -> List[List[float]]:
    """
    If you prefer OpenAI embedding as fallback replace with openai API calls.
    """
    raise NotImplementedError("Implement OpenAI fallback if desired")

def embed_texts(texts: List[str]) -> List[List[float]]:
    if GENAI_AVAILABLE:
        return embed_texts_vertex(texts)
    # fallback: simple hashing -> not recommended for production but helps run locally
    out = []
    for t in texts:
        # deterministic pseudo embedding (NOT semantically meaningful)
        h = abs(hash(t)) % (10**8)
        vec = np.zeros(DIM, dtype=np.float32)
        vec[0] = float(h % 1000) / 1000.0
        out.append(vec.tolist())
    return out

# ---------- Indexing ----------
def chunk_text(text: str, max_chars: int = 1000) -> List[str]:
    # naive chunking by characters, break on paragraphs where possible
    parts = []
    while text:
        if len(text) <= max_chars:
            parts.append(text)
            break
        # try to split at last newline before max_chars
        split_at = text.rfind("\n", 0, max_chars)
        if split_at == -1:
            split_at = max_chars
        parts.append(text[:split_at].strip())
        text = text[split_at:].strip()
    return parts

def index_corpus_dir(corpus_dir: str, overwrite: bool = False):
    """
    Walk files under corpus_dir (supports .txt, .md, .pdf)
    Create embeddings, upsert into FAISS index and save metadata.json
    """
    import glob
    from pathlib import Path
    from pypdf import PdfReader

    corpus = []
    for path in Path(corpus_dir).rglob("*"):
        if path.suffix.lower() in [".txt", ".md"]:
            corpus.append(path)
        elif path.suffix.lower() == ".pdf":
            corpus.append(path)
    docs = []
    for p in corpus:
        if p.suffix.lower() in [".txt", ".md"]:
            text = p.read_text(encoding="utf-8")
        elif p.suffix.lower() == ".pdf":
            try:
                reader = PdfReader(str(p))
                text = "\n".join(page.extract_text() or "" for page in reader.pages)
            except Exception:
                text = ""
        else:
            continue
        chunks = chunk_text(text, max_chars=1200)
        for i, c in enumerate(chunks):
            docs.append({
                "source": str(p),
                "chunk_index": i,
                "text": c[:20000]  # cap
            })

    # embed texts in batches
    texts = [d["text"] for d in docs]
    print(f"[index] embedding {len(texts)} chunks")
    vectors = embed_texts(texts)

    # build or load faiss index
    if overwrite or not INDEX_FILE.exists():
        index = faiss.IndexFlatL2(DIM)
    else:
        index = faiss.read_index(str(INDEX_FILE))

    # convert to numpy
    arr = np.array(vectors).astype("float32")
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    if index.ntotal == 0:
        index.add(arr)
        ids = list(range(index.ntotal - arr.shape[0], index.ntotal))
    else:
        # append by merging: easiest approach is to create a new index containing previous + new
        # but here we just add
        index.add(arr)
        ids = list(range(index.ntotal - arr.shape[0], index.ntotal))

    # metadata: map index id to doc metadata
    metadata = []
    if METADATA_FILE.exists() and not overwrite:
        metadata = json.loads(METADATA_FILE.read_text())
    start_id = len(metadata)
    for i, d in enumerate(docs):
        metadata.append({
            "id": start_id + i,
            "source": d["source"],
            "chunk_index": d["chunk_index"],
            "text": d["text"][:10000]
        })

    # write index & metadata
    faiss.write_index(index, str(INDEX_FILE))
    METADATA_FILE.write_text(json.dumps(metadata, indent=2))

    print("[index] done. index size:", index.ntotal)
    return {"indexed": len(docs)}

# ---------- Retrieval ----------
def load_index():
    if not INDEX_FILE.exists() or not METADATA_FILE.exists():
        raise RuntimeError("Index not found. Run index_corpus_dir() first.")
    index = faiss.read_index(str(INDEX_FILE))
    metadata = json.loads(METADATA_FILE.read_text())
    return index, metadata

def retrieve(query: str, k: int = 5) -> List[Dict[str, Any]]:
    index, metadata = load_index()
    vec = np.array(embed_texts([query])).astype("float32")
    D, I = index.search(vec, k)
    results = []
    for dist, idx in zip(D[0].tolist(), I[0].tolist()):
        if idx < 0 or idx >= len(metadata):
            continue
        meta = metadata[idx]
        results.append({"score": float(dist), "source": meta["source"], "text": meta["text"], "chunk_index": meta["chunk_index"]})
    return results

# ---------- Prompt builder ----------
def build_rag_prompt(user_query: str, retrieved: List[Dict[str, Any]], system_instructions: Optional[str] = None, max_context_chars: int = 4000) -> str:
    if system_instructions is None:
        system_instructions = (
            "You are the Sociovia Assistant. Answer concisely and only use the provided documents. "
            "If you don't know, say you don't know. When suggesting an action for the UI, append a JSON action block like: "
            '{"type":"create_ticket","payload":{...}} at the end of your reply.'  # instruct structure
        )
    # combine retrieved documents, respecting size
    context = []
    total = 0
    for r in retrieved:
        snippet = r["text"]
        if total + len(snippet) > max_context_chars:
            snippet = snippet[: max_context_chars - total]
        context.append(f"--- Source: {r['source']} (chunk {r['chunk_index']}) ---\n{snippet}\n")
        total += len(snippet)
        if total >= max_context_chars:
            break
    assembled = "\n\n".join(context)
    prompt = f"{system_instructions}\n\nCONTEXT:\n{assembled}\n\nUSER QUERY: {user_query}\n\nAnswer based ONLY on the provided CONTEXT and include sources where relevant. If you propose an action, return it as a JSON object at the end of response."
    return prompt
