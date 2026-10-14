from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Generator

import chromadb
import numpy as np
from langchain_chroma import Chroma
from langchain_core.documents import Document


_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "ollama").lower().strip()
_DEFAULTS = {
    "huggingface": "sentence-transformers/all-mpnet-base-v2",
    "ollama":      "mxbai-embed-large",
}
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", _DEFAULTS.get(_PROVIDER, _DEFAULTS["ollama"]))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

OLLAMA_EMBED_BATCH_SIZE = int(os.getenv("OLLAMA_EMBED_BATCH_SIZE", "16"))
OLLAMA_EMBED_MAX_RETRIES = int(os.getenv("OLLAMA_EMBED_MAX_RETRIES", "4"))
OLLAMA_EMBED_RETRY_BASE_S = float(os.getenv("OLLAMA_EMBED_RETRY_BASE_S", "2.0"))

COLLECTION_METADATA = {"hnsw:space": "cosine"}


class _NormalisedEmbeddings:
    def __init__(self, base, sub_batch_size=None):
        self._base = base
        self._sub_batch_size = sub_batch_size

    @staticmethod
    def _norm(vecs):
        arr   = np.array(vecs, dtype=np.float32)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        return (arr / norms).tolist()

    def _embed_batch_with_retry(self, texts):
        last_exc = None
        for attempt in range(OLLAMA_EMBED_MAX_RETRIES):
            try:
                return self._base.embed_documents(texts)
            except Exception as exc:
                last_exc = exc
                wait_s = OLLAMA_EMBED_RETRY_BASE_S * (2 ** attempt)
                print(f"    [embed] batch of {len(texts)} failed "
                      f"(attempt {attempt + 1}/{OLLAMA_EMBED_MAX_RETRIES}): "
                      f"{type(exc).__name__}: {exc}. Retrying in {wait_s:.0f}s...")
                time.sleep(wait_s)

        if len(texts) == 1:
            preview = texts[0][:200].replace("\n", " ")
            print(f"    [embed] GIVING UP on 1 document after "
                  f"{OLLAMA_EMBED_MAX_RETRIES} retries: {preview!r}")
            raise last_exc

        mid = len(texts) // 2
        print(f"    [embed] bisecting batch of {len(texts)} into "
              f"{mid} + {len(texts) - mid} to isolate the failure...")
        left = self._embed_batch_with_retry(texts[:mid])
        right = self._embed_batch_with_retry(texts[mid:])
        return left + right

    def embed_documents(self, texts):
        if not self._sub_batch_size or len(texts) <= self._sub_batch_size:
            vecs = self._embed_batch_with_retry(texts) if self._sub_batch_size else self._base.embed_documents(texts)
            return self._norm(vecs)

        all_vecs = []
        n = len(texts)
        n_batches = (n + self._sub_batch_size - 1) // self._sub_batch_size
        for i in range(0, n, self._sub_batch_size):
            batch_idx = i // self._sub_batch_size + 1
            batch = texts[i:i + self._sub_batch_size]
            print(f"    [embed] batch {batch_idx}/{n_batches} ({len(batch)} docs)...")
            all_vecs.extend(self._embed_batch_with_retry(batch))
        return self._norm(all_vecs)

    def embed_query(self, text):
        return self._norm([self._base.embed_query(text)])[0]


def _get_embeddings():
    if _PROVIDER == "ollama":
        try:
            from langchain_ollama import OllamaEmbeddings
        except ImportError:
            print("ERROR: langchain-ollama not installed. Run: pip install langchain-ollama")
            sys.exit(1)
        print(f"[05] Embedding provider : Ollama")
        print(f"[05] Model             : {EMBEDDING_MODEL}")
        print(f"[05] Ollama URL        : {OLLAMA_BASE_URL}")
        print(f"[05] Sub-batch size    : {OLLAMA_EMBED_BATCH_SIZE} "
              f"(override with OLLAMA_EMBED_BATCH_SIZE env var)")
        base = OllamaEmbeddings(model=EMBEDDING_MODEL, base_url=OLLAMA_BASE_URL)
        return _NormalisedEmbeddings(base, sub_batch_size=OLLAMA_EMBED_BATCH_SIZE)

    from langchain_huggingface import HuggingFaceEmbeddings
    print(f"[05] Embedding provider : HuggingFace")
    print(f"[05] Model             : {EMBEDDING_MODEL}")
    return HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


CHROMA_HOST     = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT     = int(os.getenv("CHROMA_PORT", "8000"))
COLLECTION_NAME = "tf_schema_properties"


KG_FILE = Path("tf_knowledge_graph.json")


def _flatten_block(
    resource_name: str,
    block_path: str,
    block_data: dict,
    depth: int = 0,
) -> Generator[Document, None, None]:
    if depth > 6:
        return

    attr_names = list(block_data.get("attributes", {}).keys())
    block_text = (
        f"Resource: {resource_name}\n"
        f"Block: {block_path}\n"
        f"Nesting: {block_data.get('nesting_mode', 'single')}\n"
        + (f"Attributes: {', '.join(attr_names[:20])}\n" if attr_names else "")
    )
    yield Document(
        page_content=block_text,
        metadata={
            "resource_name": resource_name,
            "block_path":    block_path,
            "chunk_type":    "block",
            "iac_type":      "terraform",
        },
    )

    for attr_name, attr_data in block_data.get("attributes", {}).items():
        attr_path = f"{block_path}.{attr_name}"
        desc = attr_data.get("description", "").strip()
        req  = "required" if attr_data.get("required") else "optional"
        text = (
            f"Resource: {resource_name}\n"
            f"Block attribute: {attr_path}\n"
            f"Type: {attr_data.get('type', 'unknown')}\n"
            f"Required: {req}\n"
            + (f"Description: {desc}\n" if desc else "")
        )
        yield Document(
            page_content=text,
            metadata={
                "resource_name": resource_name,
                "block_path":    attr_path,
                "chunk_type":    "block_attribute",
                "iac_type":      "terraform",
            },
        )

    for child_name, child_data in block_data.get("block_types", {}).items():
        yield from _flatten_block(
            resource_name, f"{block_path}.{child_name}", child_data, depth + 1
        )


def generate_documents(kg: dict) -> list[Document]:
    docs: list[Document] = []

    for resource_name, resource_data in kg.items():
        desc        = resource_data.get("description", "").strip()
        subcategory = resource_data.get("subcategory", "").strip()

        resource_text = (
            f"Resource: {resource_name}\n"
            + (f"Description: {desc}\n" if desc else "")
            + (f"Category: {subcategory}\n" if subcategory else "")
        )
        docs.append(Document(
            page_content=resource_text,
            metadata={
                "resource_name": resource_name,
                "chunk_type":    "resource",
                "iac_type":      "terraform",
            },
        ))

        for attr_name, attr_data in resource_data.get("attributes", {}).items():
            attr_desc = attr_data.get("description", "").strip()
            req       = "required" if attr_data.get("required") else "optional"
            text = (
                f"Resource: {resource_name}\n"
                f"Attribute: {attr_name}\n"
                f"Type: {attr_data.get('type', 'unknown')}\n"
                f"Required: {req}\n"
                + (f"Description: {attr_desc}\n" if attr_desc else "")
            )
            docs.append(Document(
                page_content=text,
                metadata={
                    "resource_name": resource_name,
                    "attribute":     attr_name,
                    "chunk_type":    "attribute",
                    "iac_type":      "terraform",
                },
            ))

        for block_name, block_data in resource_data.get("block_types", {}).items():
            docs.extend(_flatten_block(resource_name, block_name, block_data))

        for i, example_code in enumerate(resource_data.get("examples", [])):
            docs.append(Document(
                page_content=(
                    f"Terraform HCL example for {resource_name}:\n{example_code}"
                ),
                metadata={
                    "resource_name": resource_name,
                    "chunk_type":    "example",
                    "example_index": i,
                    "iac_type":      "terraform",
                },
            ))

    return docs


def build_vector_db() -> None:
    embeddings = _get_embeddings()

    print(f"[05] Loading {KG_FILE} ...")
    kg = json.loads(KG_FILE.read_text(encoding="utf-8"))
    print(f"[05] {len(kg):,} resources loaded.")

    print(f"[05] Generating document chunks ...")
    documents = generate_documents(kg)
    print(f"[05] {len(documents):,} chunks ready.")

    print(f"[05] Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT} ...")
    chroma_client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)

    existing = [c.name for c in chroma_client.list_collections()]
    if COLLECTION_NAME in existing:
        print(f"[05] Dropping existing collection '{COLLECTION_NAME}' for clean rebuild ...")
        chroma_client.delete_collection(COLLECTION_NAME)

    print(f"[05] Embedding and ingesting into '{COLLECTION_NAME}' ...")
    Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        client=chroma_client,
        collection_name=COLLECTION_NAME,
        collection_metadata=COLLECTION_METADATA,
    )

    print(f"\n[05] Done.")
    print(f"     Provider   : {_PROVIDER}")
    print(f"     Model      : {EMBEDDING_MODEL}")
    print(f"     Chunks     : {len(documents):,}")
    print(f"     Collection : {COLLECTION_NAME} @ {CHROMA_HOST}:{CHROMA_PORT}")
    print(f"     Distance   : cosine (hnsw:space=cosine)")
    print(f"     Normalised : True")


if __name__ == "__main__":
    build_vector_db()
