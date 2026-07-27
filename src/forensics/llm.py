"""LLM provider fallback chain: Ollama -> Groq -> Gemini -> offline summary."""

import os
import re
import urllib.request

from .context import extract_system_context

GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL_ID = "gemini-2.0-flash"
gemini_client   = None
if GEMINI_API_KEY:
    try:
        from google import genai
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        print("  [OK] Gemini LLM configured (Modern SDK).")
    except Exception as e:
        print(f"  [WARN] Gemini init failed: {e}")
else:
    print("  [WARN] GEMINI_API_KEY not set — Gemini unavailable.")

# ── Groq (cloud fallback) ─────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
groq_client  = None
if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("  [OK] Groq LLM configured (Fallback ready).")
    except ImportError:
        print("  [WARN] Groq key found but 'groq' package missing. Run: pip install groq")
else:
    print("  [WARN] GROQ_API_KEY not set — Groq unavailable.")

# ── Ollama (local, no rate limits) ────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "llama3.2")

def check_ollama_available():
    """Returns True if Ollama server is reachable."""
    try:
        req = urllib.request.urlopen(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
        return req.status == 200
    except Exception:
        return False

ollama_available = check_ollama_available()
if ollama_available:
    print(f"  [OK] Ollama available at {OLLAMA_BASE_URL} — model: {OLLAMA_MODEL}")
else:
    print(f"  [WARN] Ollama not reachable at {OLLAMA_BASE_URL}. "
          f"Start it with: ollama serve")

# ── Safety check: at least one LLM must be available ─────────────────────
def ensure_llm_available():
    """Raise if no provider is usable. Called at app startup, not import time."""
    if gemini_client or groq_client or ollama_available:
        return
    raise RuntimeError(
        "[ERROR] No LLM available. Either:\n"
        "  • Set GEMINI_API_KEY in .env\n"
        "  • Set GROQ_API_KEY in .env\n"
        "  • Run: ollama serve"
    )


def format_evidence_block(evidence_context, max_lines=5):
    """Cite the tags of the top matches so the UI can resolve them to full evidence."""
    if not evidence_context:
        return ""
    tags = re.findall(r'\[(E\d+)\]', evidence_context)[:max_lines]
    if not tags:
        return ""
    return " ".join(f"[{t}]" for t in tags)


def build_offline_response(user_question, evidence_context, session):
    system_facts = extract_system_context(session)
    tags = format_evidence_block(evidence_context)
    tag_line = f"\n\nTop matching evidence: {tags}" if tags else ""
    return (
        "*No LLM provider is currently reachable — showing a deterministic summary "
        "instead of an AI analysis.*\n\n"
        f"**System facts**\n```\n{system_facts}\n```"
        f"{tag_line}"
    )


def query_ollama(prompt, system_prompt):
    """
    Send a prompt to a locally running Ollama instance.
    No API key required. No rate limits.
    """
    import json as _json
    import urllib.request as _req

    payload = _json.dumps({
        "model":  OLLAMA_MODEL,
        "prompt": f"{system_prompt}\n\n{prompt}",
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 400,   
        }
    }).encode("utf-8")

    try:
        request = _req.Request(
            f"{OLLAMA_BASE_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with _req.urlopen(request, timeout=60) as resp:
            result = _json.loads(resp.read().decode("utf-8"))
            return result.get("response", "").strip()
    except Exception as e:
        print(f"  [OLLAMA] Query failed: {e}")
        return None


def query_llm(user_question, evidence_context, session):
    if session.cached_system_facts is None:
        print("  [CACHE] Regenerating system facts...")
        session.cached_system_facts = extract_system_context(session)

    system_facts = session.cached_system_facts

    system_prompt = f"""You are a Senior Digital Forensics Examiner writing a professional case report.
Analyze the provided evidence and answer the investigator's question clearly and concisely.

── GLOBAL SYSTEM FACTS ──
{system_facts}

FORMATTING RULES (STRICT):
1. Write in clean professional prose. Use **bold** for key findings, usernames, timestamps, and suspicious items.
2. Use bullet points only when listing multiple discrete items.
3. CITE YOUR SOURCES. Every factual claim drawn from the retrieved evidence must carry an
   inline citation tag matching the evidence it came from, e.g. "the audit log was cleared at
   **03:02** [E2]". Cite the specific tag(s) you used — never invent a tag that was not provided.
4. If the retrieved evidence does not answer the question, say so plainly rather than guessing.
   Facts taken from GLOBAL SYSTEM FACTS above need no citation tag.
5. DO NOT paste raw evidence lines verbatim, and do not add your own "EVIDENCE" section —
   the interface appends the cited evidence automatically below your answer.
6. End with a short "**Key Finding:**" line summarizing the most important discovery.
7. Keep responses under 180 words total."""

    prompt = f"""── RETRIEVED EVIDENCE ──
{evidence_context}

── INVESTIGATOR'S QUESTION ──
{user_question}

── YOUR FORENSIC ANALYSIS ──"""

    
    if ollama_available:
        result = query_ollama(prompt, system_prompt)
        if result:
            print("  [LLM] Response from Ollama")
            return result
        else:
            print("  [LLM] Ollama failed, falling back...")

   
    if groq_client:
        try:
            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": prompt}
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.2,
            )
            print("  [LLM] Response from Groq")
            return chat_completion.choices[0].message.content
        except Exception as e:
            print(f"  [LLM] Groq error: {e}")

    # ── Priority 3: Gemini (cloud fallback) ───────────────────────────────
    if gemini_client:
        try:
            response = gemini_client.models.generate_content(
                model=GEMINI_MODEL_ID,
                contents=prompt,
                config={"system_instruction": system_prompt, "temperature": 0.1}
            )
            print("  [LLM] Response from Gemini")
            return response.text
        except Exception as e:
            print(f"  [LLM] Gemini error: {e}")

    # ── Priority 4: Offline deterministic summary ─────────────────────────
    print("  [LLM] All providers failed — returning deterministic summary")
    return build_offline_response(user_question, evidence_context, session)
