import pandas as pd
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import pickle
import os

# 1. Load your forensic data
csv_path = "../unified_forensic_data.csv"
print(f"Loading data from {csv_path}...")
df = pd.read_csv(csv_path, low_memory=False)

# Clean column names
df.columns = df.columns.str.strip()

# --- THE BULLETPROOF FIX ---
print("Forcing all data to text format to prevent crashes...")

# 1. Force the columns to string and fill empty spots with 'None'
df['Task Category'] = df['Task Category'].fillna('No Description').astype(str)
df['LogSource'] = df.get('LogSource', 'Unknown').fillna('Unknown').astype(str)
df['Event ID'] = df.get('Event ID', '0').fillna('0').astype(str)

# 2. Create the input and FORCE the entire series to be string again
# This is the 'Double Lock' that ensures no floats slip through
df['ai_input'] = (
    "Source: " + df['LogSource'] + 
    " | Event: " + df['Event ID'] + 
    " | Description: " + df['Task Category']
).astype(str)

# 3. Final safety check: If anything is still not a string, make it one
ai_input_list = [str(item) for item in df['ai_input'].tolist()]

# ----------------------------

# 2. Load the Deep Learning Model
print("\nLoading Deep Learning Model (Transformer)...")
model = SentenceTransformer('all-MiniLM-L6-v2')

# 3. Generate the Embeddings
print(f"Embedding {len(df)} logs. This is the final run!")
# We use the 'ai_input_list' which we explicitly forced to be strings.
# Chunked encoding keeps terminal feedback readable and avoids long silent waits.
batch_size = 128
chunks = []
for start in range(0, len(ai_input_list), batch_size):
    end = min(start + batch_size, len(ai_input_list))
    chunk = ai_input_list[start:end]
    chunk_embeddings = model.encode(
        chunk,
        batch_size=batch_size,
        show_progress_bar=False,
        convert_to_numpy=True
    )
    chunks.append(chunk_embeddings)
    print(f"  [EMBED] Processed {end}/{len(ai_input_list)}")

embeddings = np.vstack(chunks).astype('float32')

# 4. Build the FAISS Vector Index
print("Building the Vector Search Index...")
dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(embeddings)

# 5. Save the Index and Metadata
faiss.write_index(index, "forensic_vdb.index")
meta_cols = ['Date and Time', 'Source', 'Event ID', 'Task Category', 'LogSource']
existing_meta = [c for c in meta_cols if c in df.columns]
df[existing_meta].to_pickle("metadata.pkl")

print("\n" + "="*40)
print("SUCCESS: THE BRAIN IS FULLY BUILT")
print("="*40)