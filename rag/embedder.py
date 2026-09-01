"""
rag/embedder.py
---------------
SENTINEL-X local embedding layer using sentence-transformers.

Provides SentinelEmbedder, a lazy-loading wrapper around
``all-MiniLM-L6-v2`` that serialises/deserialises float32 vectors
as raw bytes for SQLite BLOB storage.
"""

from __future__ import annotations

from typing import Optional

import numpy as np


class SentinelEmbedder:
    """Lazy-loading sentence-transformer embedder.

    The underlying model is only downloaded and loaded the first time an
    embedding is requested, keeping import time fast.

    Parameters
    ----------
    model_name:
        HuggingFace model identifier.  Defaults to the lightweight
        ``all-MiniLM-L6-v2`` (384-d, ~22 M params).
    device:
        ``"cpu"`` or ``"cuda"``.  ``None`` lets sentence-transformers
        pick automatically.
    """

    MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"
    EMBEDDING_DIM: int = 384

    def __init__(
        self,
        model_name: str = MODEL_NAME,
        device: Optional[str] = None,
    ) -> None:
        self._model_name: str = model_name
        self._device: Optional[str] = device
        self._model = None  # lazy-loaded

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load the sentence-transformer model on first use."""
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is not installed. "
                "Run: pip install sentence-transformers"
            ) from exc

        self._model = SentenceTransformer(self._model_name, device=self._device)

    @property
    def model_name(self) -> str:
        """Return the model identifier string."""
        return self._model_name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed(self, text: str) -> np.ndarray:
        """Embed a single text string.

        Parameters
        ----------
        text:
            Input text to embed.

        Returns
        -------
        np.ndarray
            Float32 vector of shape ``(EMBEDDING_DIM,)``.
        """
        if not isinstance(text, str):
            raise TypeError(f"embed() expects str, got {type(text).__name__}")
        self._load_model()
        vector: np.ndarray = self._model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
        ).astype(np.float32)
        return vector

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        """Embed a list of texts in one batched forward pass.

        Parameters
        ----------
        texts:
            List of strings to embed.

        Returns
        -------
        np.ndarray
            Float32 matrix of shape ``(len(texts), EMBEDDING_DIM)``.
        """
        if not texts:
            return np.empty((0, self.EMBEDDING_DIM), dtype=np.float32)
        self._load_model()
        vectors: np.ndarray = self._model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        ).astype(np.float32)
        return vectors

    def embed_blob(self, text: str) -> bytes:
        """Embed text and serialise the float32 vector as raw bytes.

        Suitable for storing directly in a SQLite BLOB column.

        Parameters
        ----------
        text:
            Input text to embed.

        Returns
        -------
        bytes
            Little-endian IEEE-754 float32 values concatenated.
        """
        return self.embed(text).tobytes()

    @staticmethod
    def from_blob(blob: bytes) -> np.ndarray:
        """Deserialise a raw-bytes BLOB back to a float32 numpy vector.

        Parameters
        ----------
        blob:
            Bytes produced by :meth:`embed_blob`.

        Returns
        -------
        np.ndarray
            Float32 vector of shape ``(N,)`` where N = len(blob) // 4.
        """
        if not blob:
            raise ValueError("Cannot deserialise an empty BLOB.")
        return np.frombuffer(blob, dtype=np.float32).copy()

    @staticmethod
    def cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors.

        Handles zero-norm vectors gracefully by returning 0.0.

        Parameters
        ----------
        a, b:
            1-D float32 arrays of equal length.

        Returns
        -------
        float
            Similarity in ``[-1.0, 1.0]``.
        """
        norm_a = float(np.linalg.norm(a))
        norm_b = float(np.linalg.norm(b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))


# ---------------------------------------------------------------------------
# Quick smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    embedder = SentinelEmbedder()
    v1 = embedder.embed("SSH brute-force attack detected")
    v2 = embedder.embed("Multiple failed login attempts over SSH")
    blob = embedder.embed_blob("test blob serialisation")
    restored = SentinelEmbedder.from_blob(blob)

    print(f"Embedding dim : {v1.shape}")
    print(f"Dtype         : {v1.dtype}")
    print(f"Cosine sim    : {SentinelEmbedder.cosine_sim(v1, v2):.4f}")
    print(f"Blob len      : {len(blob)} bytes")
    print(f"Restored shape: {restored.shape}")
    print("SentinelEmbedder OK")