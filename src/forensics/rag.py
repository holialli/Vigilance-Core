"""FAISS-backed retrieval over activity artifacts."""

import os
import re
import time

import numpy as np

from .config import CACHE_DIR
from .embedding import encode_bulk, encode_query

# faiss is imported lazily, inside the functions that need it, rather than at
# module scope. Measured: an encode child spawned from a parent that has already
# imported faiss died before finishing a single chunk in 5 runs out of 5, while
# the same child from a parent without it got through 2 chunks or more in 3 runs
# out of 5. The mechanism is not understood — the two are separate processes,
# and neither the inherited environment nor the CPU affinity mask differs — so
# treat this as an observed association, not a theory. Deferring the import is
# free, and it means a *fresh* index build does its encoding before faiss is
# ever loaded here. Once faiss is in, it stays for the life of the process.

# Bulk types are embedded into FAISS. FILESYSTEM is excluded: its MFT dump is far
# too large and repetitive to embed usefully, and file-count questions are served
# by extract_system_context() instead.
EMBED_TYPES = {'EVTX', 'REGISTRY', 'SAM', 'SOFTWARE'}

# High-value but low-volume artifacts (tens of rows, not tens of thousands).
# Scanned lexically on every query rather than embedded: they are too rare to
# ever win a pure vector search against 50k+ registry rows, and keeping them out
# of the index means adding a type here never invalidates a built index.
LEXICAL_TYPES = {
    'USB', 'BROWSER', 'PREFETCH', 'RECYCLE', 'ACTIVITY', 'RECENT',
    'COMMUNICATION', 'USN', 'SRUM',
}

# Maps investigator phrasing to the artifact types that actually answer it, so a
# question about USB devices ranks 15 USB rows above 54k registry rows.
TYPE_ROUTING = {
    'USB':           [r'\busb\b', r'thumb ?drive', r'removable', r'external (drive|disk)', r'flash drive'],
    'BROWSER':       [r'browser', r'\burls?\b', r'website', r'visit', r'bookmark', r'cookie', r'browsing', r'download'],
    'SAM':           [r'user account', r'\busers?\b', r'\baccounts?\b', r'\blogons?\b', r'\blogins?\b'],
    'SOFTWARE':      [r'install', r'program', r'software', r'application'],
    'PREFETCH':      [r'prefetch', r'execut', r'\bran\b', r'launch'],
    'RECYCLE':       [r'recycle', r'delet'],
    'COMMUNICATION': [r'e-?mail', r'\bmail\b', r'outlook', r'\bpst\b', r'message'],
    'RECENT':        [r'recent', r'\bopened\b', r'document'],
    'ACTIVITY':      [r'\blnk\b', r'jump ?list', r'shortcut'],
    'REGISTRY':      [r'registry', r'persistence', r'autostart', r'\brun ?key'],
    'EVTX':          [r'event ?log', r'\bevtx\b', r'audit', r'security log', r'cleared'],
}

_STOPWORDS = {
    'the', 'a', 'an', 'is', 'are', 'was', 'were', 'any', 'all', 'show', 'me',
    'what', 'which', 'who', 'when', 'list', 'find', 'there', 'this', 'that',
    'on', 'in', 'of', 'to', 'for', 'and', 'or', 'do', 'did', 'does', 'have',
    'has', 'system', 'were', 'from', 'with', 'by', 'be',
}


def _dedup_shape(text):
    """Structural fingerprint used to collapse near-identical artifact rows."""
    t = text.lower()
    t = re.sub(r'\{[0-9a-f\-]{36}\}', '<guid>', t)
    t = re.sub(r'\d+', '#', t)
    t = re.sub(r'[\\/]+', '/', t)
    return t[:120]


def _query_terms(query):
    return {t for t in re.findall(r'[a-z0-9]+', query.lower())
            if len(t) > 2 and t not in _STOPWORDS}


def _routed_types(query):
    q = query.lower()
    return {t for t, pats in TYPE_ROUTING.items()
            if any(re.search(p, q) for p in pats)}


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
    if session.current_audit_df is None:
        return [], ""

    types_upper = session.current_audit_df['ArtifactType'].astype(str).str.upper()

    embed_df = session.current_audit_df[types_upper.isin(EMBED_TYPES)].copy()
    embed_df = embed_df.drop_duplicates(subset=['Task Category']).reset_index(drop=True)

    lexical_df = session.current_audit_df[types_upper.isin(LEXICAL_TYPES)].copy()
    lexical_df = lexical_df.drop_duplicates(subset=['Task Category']).reset_index(drop=True)
    # ─────────────────────────────────────────────────────────────────────────

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
                import faiss
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

                # Encoded in child processes: four OpenMP runtimes in one
                # process crash this call, and a segfault here would take the
                # Gradio server down rather than failing this one build. Note
                # this runs *before* faiss is imported below, deliberately.
                # See embedding.py.
                #
                # Finished chunks go in the case directory, not a temp dir, so a
                # build that gives up can be resumed rather than repeated. On
                # this image that is over an hour of encoding worth keeping.
                chunk_dir = (os.path.join(CACHE_DIR, session.image_hash_sha256,
                                          "embed_chunks")
                             if session.image_hash_sha256 else None)
                # No batch_size here: embedding.py owns that number, and it is
                # the one that decides whether the child fits in memory. This
                # call used to pin it to 256, which overrode the default and
                # put every child 400 MB over what this box can commit.
                unique_embeddings = encode_bulk(normalized_texts,
                                                work_dir=chunk_dir)

                # Map unique embeddings back to the full filtered series
                text_to_idx = {text: i for i, text in enumerate(unique_texts)}
                idx_map = texts_series.map(text_to_idx).values
                full_embeddings = unique_embeddings[idx_map]

                import faiss
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

    # ── Hybrid retrieval ─────────────────────────────────────────────────────
    # Vector search alone drowns rare-but-relevant artifacts (15 USB rows) under
    # bulk registry noise, so semantic hits are merged with lexical hits and
    # type-routed candidates, then rescored before truncating to top_k.
    terms = _query_terms(query)
    routed = _routed_types(query)

    scored = []  # (score, source_df, positional_index)

    query_vec = encode_query(query)
    n_semantic = min(max(top_k * 8, 40), len(embed_df))
    distances, result_indices = session.faiss_index.search(
        np.array(query_vec).astype('float32'), k=n_semantic
    )
    semantic_scores = {}
    for dist, idx in zip(distances[0], result_indices[0]):
        if 0 <= idx < len(embed_df):
            semantic_scores[int(idx)] = 1.0 / (1.0 + float(dist))

    scored.extend(
        _score_frame(embed_df, semantic_scores, terms, routed, n_semantic)
    )
    scored.extend(
        _score_frame(lexical_df, {}, terms, routed, n_semantic)
    )

    scored.sort(key=lambda item: item[0], reverse=True)

    relevant_rows = []
    context_lines = []

    for score, frame, idx in scored[:top_k]:
        row = frame.iloc[idx]
        tag = f"E{len(relevant_rows) + 1}"
        relevant_rows.append({
            "tag": tag,
            "time": str(row.get('Date and Time', 'N/A')),
            "event_id": str(row.get('Event ID', 'N/A')),
            "source": str(row.get('LogSource', 'N/A')),
            "artifact_type": str(row.get('ArtifactType', 'N/A')),
            "description": str(row.get('Task Category', 'N/A')),
            "score": round(float(score), 4),
        })
        context_lines.append(
            f"[{tag}] "
            f"Time: {row.get('Date and Time', 'N/A')} | "
            f"EventID: {row.get('Event ID', 'N/A')} | "
            f"Source: {row.get('LogSource', 'N/A')} | "
            f"Description: {row.get('Task Category', 'N/A')}"
        )

    return relevant_rows, "\n".join(context_lines)


def _score_frame(frame, semantic_scores, terms, routed, limit):
    """Score candidate rows of one frame by semantic + lexical + type-routing."""
    if frame is None or frame.empty:
        return []

    descriptions = frame['Task Category'].fillna('').astype(str).str.lower()
    types_upper = frame['ArtifactType'].fillna('').astype(str).str.upper()

    candidates = set(semantic_scores)

    if terms:
        hits = descriptions.apply(lambda d: sum(1 for t in terms if t in d))
        candidates.update(int(i) for i in hits.nlargest(limit).index if hits[i] > 0)

    if routed:
        routed_positions = [i for i, t in enumerate(types_upper) if t in routed]
        candidates.update(routed_positions[:limit])

    results = []
    seen_shapes = set()
    for idx in candidates:
        desc = descriptions.iat[idx]

        # Collapse near-identical rows (e.g. thousands of CMI-CreateHive registry
        # keys differing only by path) so one noisy family cannot fill top_k.
        shape = _dedup_shape(desc)
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)

        lexical = (sum(1 for t in terms if t in desc) / len(terms)) if terms else 0.0
        score = semantic_scores.get(idx, 0.0) + 0.5 * lexical

        if routed:
            # When the question clearly targets an artifact type, demote everything
            # else: otherwise 50k semantically-similar registry rows bury the 15
            # USB rows that actually answer it.
            score = score + 0.35 if types_upper.iat[idx] in routed else score * 0.35

        results.append((score, frame, idx))
    return results


def cited_tags(answer_text):
    """Every evidence tag an answer references.

    Models group citations as "[E3, E4, E6]" as readily as they write "[E3]".
    Matching only the single-tag form silently dropped the grouped ones from the
    appendix, so evidence the answer actually relied on became unverifiable.
    """
    tags = set()
    for group in re.findall(r'\[((?:\s*E\d+\s*[,;]?)+)\]', answer_text or ""):
        tags.update(re.findall(r'E\d+', group))
    return tags


def format_citations(rows, cited_only=True, answer_text=""):
    """Render retrieved evidence as a markdown appendix for the chat/report."""
    if not rows:
        return ""

    shown = rows
    if cited_only and answer_text:
        referenced = cited_tags(answer_text)
        if referenced:
            shown = [r for r in rows if r["tag"] in referenced]

    if not shown:
        return ""

    lines = ["", "---", f"**Evidence ({len(shown)})**", ""]
    for r in shown:
        desc = r["description"]
        if len(desc) > 240:
            desc = desc[:240] + "…"
        lines.append(
            f"- **[{r['tag']}]** `{r['time']}` · {r['artifact_type']}/{r['source']} "
            f"· Event {r['event_id']}  \n  {desc}"
        )
    return "\n".join(lines)
