import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import time
import sqlite3
import json
import logging
from typing import List, Dict, Optional, Any
from app.utils.config import Config

class MemoryVectorStore:
    """Efficient vector store for conversation memory with FAISS indexing."""
    def __init__(self, config: Config):
        self.config = config
        self.embedding_model = SentenceTransformer(config.embedding_model)
        self.dim = self.embedding_model.get_sentence_embedding_dimension()
        self.index = faiss.IndexFlatL2(self.dim)
        self.memories: List[Dict[str, Any]] = []
        self.max_memories = config.max_memories
        self.batch_size = config.embedding_batch_size
        self.tiers = {"short": 0.5, "medium": 0.7, "long": 0.9}
        self.decay_rate = config.memory_decay_rate
        self.favorites = set()
        self.interaction_counts: Dict[int, int] = {}
        self.user_feedback_scores: Dict[int, float] = {}
        self.next_id = 0
        self.cold_storage: List[Dict[str, Any]] = []
        self.db_path = "app/memory_store.db"
        self.setup_disk_storage()
        self.last_reembedding_time = time.time()
        self.reembedding_interval = 3600 * 24 * 7
        logging.info(f"MemoryVectorStore initialized with dimension {self.dim}")

    def setup_disk_storage(self):
        """Set up SQLite database for disk-based cold storage."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cold_memories (
                    id INTEGER PRIMARY KEY,
                    text TEXT NOT NULL,
                    role TEXT NOT NULL,
                    embedding BLOB NOT NULL,
                    metadata TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    favorite INTEGER NOT NULL,
                    interaction_count INTEGER NOT NULL,
                    feedback_score REAL NOT NULL,
                    last_accessed REAL NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cold_memories_id ON cold_memories (id)')
            conn.commit()
            conn.close()
            logging.info(f"Disk-based cold storage initialized at {self.db_path}")
        except Exception as e:
            logging.error(f"Failed to initialize disk storage: {str(e)}")

    def embed(self, text: str) -> np.ndarray:
        """Create embedding for a single text."""
        try:
            return self.embedding_model.encode(text, convert_to_numpy=True, show_progress_bar=False)
        except Exception as e:
            logging.error(f"Embedding failed: {str(e)}")
            return np.zeros(self.dim)

    def add(self, text: str, role: str, metadata: Optional[Dict[str, Any]] = None) -> int:
        """Add a memory with proper management."""
        if not text.strip():
            return -1
        if len(self.memories) >= self.max_memories:
            self._prune_memories()
        embedding = self.embed(text)
        metadata = metadata or {"relevance": 1.0, "mood": "neutral"}
        memory_id = self.next_id
        self.next_id += 1
        entry = {
            "id": memory_id, "text": text, "role": role, "embedding": embedding,
            "metadata": metadata, "timestamp": time.time(), "favorite": False,
            "interaction_count": 0, "feedback_score": 0.0, "last_accessed": time.time()
        }
        self.index.add(embedding.reshape(1, -1))
        self.memories.append(entry)
        return memory_id

    def mark_as_favorite(self, memory_id: int) -> bool:
        """Mark a memory as favorite."""
        for memory in self.memories:
            if memory.get("id") == memory_id:
                memory["favorite"] = True
                self.favorites.add(memory_id)
                memory["metadata"]["relevance"] = max(
                    1.0, memory["metadata"].get("relevance", 0) * (1 + self.config.memory_favorites_boost)
                )
                return True
        # Simplified; full implementation would include cold and disk storage checks
        return False

    def retrieve(self, query: str, top_k: int = 25) -> Dict[str, List[Dict]]:
        """Retrieve relevant memories for a query."""
        if not self.memories:
            return {"short": [], "medium": [], "long": []}
        query_emb = self.embed(query)
        top_k_active = min(top_k, len(self.memories))
        distances, indices = self.index.search(query_emb.reshape(1, -1), top_k_active)
        results = []
        for d, i in zip(distances[0], indices[0]):
            if i >= 0:
                similarity = 1.0 / (1.0 + d)
                if similarity >= self.config.similarity_threshold:
                    memory = self.memories[i].copy()
                    memory["similarity"] = similarity
                    results.append(memory)
        tiered_results = {"short": [], "medium": [], "long": []}
        for memory in sorted(results, key=lambda x: x["similarity"], reverse=True):
            sim = memory["similarity"]
            if sim >= self.tiers["long"]:
                tiered_results["long"].append(memory)
            elif sim >= self.tiers["medium"]:
                tiered_results["medium"].append(memory)
            else:
                tiered_results["short"].append(memory)
        return tiered_results

    def _prune_memories(self):
        """Prune memories based on relevance (simplified)."""
        self.memories = self.memories[-self.max_memories//2:]
        self.index.reset()
        if self.memories:
            embeddings = np.vstack([m["embedding"].reshape(1, -1) for m in self.memories])
            self.index.add(embeddings)
