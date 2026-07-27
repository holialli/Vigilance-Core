"""FAISS-backed retrieval over activity artifacts."""

import os
import re
import threading
import time

import faiss
import numpy as np

from .config import CACHE_DIR

ai_model = None
_ai_model_lock = threading.Lock()

# ── FIX-3: Normalize text before embedding to maximize cache hit rate ─────
def _normalize_for_embedding(txt: str) -> str:
    """Collapse volatile tokens so semantically identical events share one vector."""
    txt = re.sub(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}(\s?UTC)?', '<TS>', txt)
    txt = re.sub(r'\{[0-9A-Fa-f\-]{36}\}', '<GUID>', txt)
    txt = re.sub(r'\b0x[0-9A-Fa-f]{4,}\b', '<HEX>', txt)
    txt = re.sub(r'\b\d{6,}\b', '<NUM>', txt)
    txt = re.sub(r'([A-Za-z]:\\|/)[^\s|]+[\\/]', '<PATH>/', txt)
    return txt.strip()

def build_rag_context(query, session, top_k=8):
    global ai_model

    if session.current_audit_df is None:
        return [], ""

    # ── REQ-1 & REQ-2: Strict filtering — Activity-Based artifacts ONLY ──────
    # FILESYSTEM (MFT) is completely excluded from FAISS embedding.
    # File count questions are answered via extract_system_context() metadata.
    EMBED_TYPES = {'EVTX', 'REGISTRY', 'SAM', 'SOFTWARE'}

    embed_mask = session.current_audit_df['ArtifactType'].str.upper().isin(EMBED_TYPES)
    embed_df = session.current_audit_df[embed_mask].copy().reset_index(drop=True)
    embed_df = embed_df.drop_duplicates(subset=['Task Category']).reset_index(drop=True)
    # ─────────────────────────────────────────────────────────────────────────

    from sentence_transformers import SentenceTransformer

    with _ai_model_lock:
        if ai_model is None:
            ai_model = SentenceTransformer('all-MiniLM-L6-v2')

    with session.faiss_lock:
        if session.faiss_index is None:
            cache_file = None
            if session.image_hash_sha256:
                case_dir = os.path.join(CACHE_DIR, session.image_hash_sha256)
                os.makedirs(case_dir, exist_ok=True)
                cache_file = os.path.join(case_dir, "faiss.index")

            # ── REQ-4: Validate cache against filtered embed_df, not full df ─
            if cache_file and os.path.exists(cache_file):
                print(f"  [FAISS] Loading cached index: {session.image_hash_sha256[:16]}...")
                loaded_index = faiss.read_index(cache_file)
                if loaded_index.ntotal == len(embed_df):
                    session.faiss_index = loaded_index
                    print(f"  [FAISS] Cache valid ({loaded_index.ntotal} vectors).")
                else:
                    print(
                        f"  [WARN] Cache size mismatch "
                        f"({loaded_index.ntotal} cached vs {len(embed_df)} filtered). "
                        f"Rebuilding..."
                    )
                    session.faiss_index = None
            # ─────────────────────────────────────────────────────────────────

            if session.faiss_index is None:
                print(f"  [FAISS] Vectorizing {len(embed_df)} activity artifacts "
                      f"(EVTX + REGISTRY + SAM + SOFTWARE only)...")
                t0 = time.time()

                texts_series = embed_df['Task Category'].fillna('').astype(str)
                unique_texts = texts_series.unique().tolist()

                # Normalize to collapse volatile tokens and improve cache hits
                normalized_texts = [_normalize_for_embedding(t) for t in unique_texts]

                # ── REQ: num_workers removed — not supported by this ST version ──
                unique_embeddings = ai_model.encode(
                    normalized_texts,
                    batch_size=256,
                    show_progress_bar=False,
                    convert_to_numpy=True,
                )
                # ─────────────────────────────────────────────────────────────

                # Map unique embeddings back to the full filtered series
                text_to_idx = {text: i for i, text in enumerate(unique_texts)}
                idx_map = texts_series.map(text_to_idx).values
                full_embeddings = unique_embeddings[idx_map]

                dim = full_embeddings.shape[1]

                # ── FIX-2: IVF only at large scale; Flat L2 for typical loads ─
                ivf_threshold = int(os.getenv("FAISS_IVF_THRESHOLD", "500"))
                n_unique = len(unique_embeddings)
                if n_unique > ivf_threshold:
                    nlist = min(int(n_unique ** 0.5), 256)
                    quantizer = faiss.IndexFlatL2(dim)
                    session.faiss_index = faiss.IndexIVFFlat(quantizer, dim, nlist)
                    session.faiss_index.train(
                        np.array(unique_embeddings).astype('float32')
                    )
                    session.faiss_index.nprobe = min(32, nlist)
                    print(f"  [FAISS] Using IVF index (nlist={nlist})")
                else:
                    session.faiss_index = faiss.IndexFlatL2(dim)
                    print(f"  [FAISS] Using Flat L2 index")
                # ─────────────────────────────────────────────────────────────

                session.faiss_index.add(np.array(full_embeddings).astype('float32'))

                if cache_file:
                    faiss.write_index(session.faiss_index, cache_file)

                elapsed = time.time() - t0
                print(f"  [FAISS] Index ready — {session.faiss_index.ntotal} vectors "
                      f"in {elapsed:.2f}s")

    # Return early if this was just an init/warmup call
    if query == "Init":
        return [], ""

    # ── REQ-5: embed_df is always defined above the lock so search is safe ───
    # Encode query — num_workers omitted for ST compatibility
    query_vec = ai_model.encode([query], convert_to_numpy=True)
    distances, result_indices = session.faiss_index.search(
        np.array(query_vec).astype('float32'), k=top_k
    )

    relevant_rows = []
    context_lines = []

    for rank, (dist, idx) in enumerate(zip(distances[0], result_indices[0])):
        if idx < 0 or idx >= len(embed_df):
            continue
        row = embed_df.iloc[idx]
        relevant_rows.append(row)
        context_lines.append(
            f"[Evidence {rank}] "
            f"Time: {row.get('Date and Time', 'N/A')} | "
            f"EventID: {row.get('Event ID', 'N/A')} | "
            f"Source: {row.get('LogSource', 'N/A')} | "
            f"Description: {row.get('Task Category', 'N/A')}"
        )

    return relevant_rows, "\n".join(context_lines)
