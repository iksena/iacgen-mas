from __future__ import annotations

import os
from functools import lru_cache

import numpy as np
from langchain_core.embeddings import Embeddings


_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "huggingface").lower().strip()

_DEFAULTS: dict[str, str] = {
    "huggingface": "sentence-transformers/all-mpnet-base-v2",
    "ollama":      "mxbai-embed-large",
}

EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", _DEFAULTS.get(_PROVIDER, _DEFAULTS["huggingface"]))
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


class _NormalisedEmbeddings(Embeddings):

    def __init__(self, base: Embeddings) -> None:
        self._base = base

    @staticmethod
    def _normalise(vecs: list[list[float]]) -> list[list[float]]:
        arr = np.array(vecs, dtype=np.float32)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        return (arr / norms).tolist()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._normalise(self._base.embed_documents(texts))

    def embed_query(self, text: str) -> list[float]:
        return self._normalise([self._base.embed_query(text)])[0]


@lru_cache(maxsize=1)
def get_embeddings() -> Embeddings:
    if _PROVIDER == "ollama":
        return _NormalisedEmbeddings(_build_ollama_embeddings())
    return _build_huggingface_embeddings()


def _build_huggingface_embeddings() -> Embeddings:
    from langchain_huggingface import HuggingFaceEmbeddings

    print(f"[Embeddings] Provider: HuggingFace  Model: {EMBEDDING_MODEL}")
    return HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


def _build_ollama_embeddings() -> Embeddings:
    try:
        from langchain_ollama import OllamaEmbeddings
    except ImportError as exc:
        raise ImportError(
            "langchain-ollama is required for EMBEDDING_PROVIDER=ollama. "
            "Install it with: pip install langchain-ollama"
        ) from exc

    print(f"[Embeddings] Provider: Ollama  Model: {EMBEDDING_MODEL}  URL: {OLLAMA_BASE_URL}")
    return OllamaEmbeddings(
        model=EMBEDDING_MODEL,
        base_url=OLLAMA_BASE_URL,
    )


def get_provider() -> str:
    return _PROVIDER


def get_model_name() -> str:
    return EMBEDDING_MODEL


CHROMA_COLLECTION_METADATA: dict[str, str] = {"hnsw:space": "cosine"}

DEFAULT_DISTANCE_THRESHOLD: float = float(
    os.getenv("CHROMA_DISTANCE_THRESHOLD", "0.40")
)
