#!/usr/bin/env python3
"""
页面视觉比对工具
优先使用感知哈希；缺少依赖时自动降级到文件哈希。
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional

try:
    from PIL import Image
    import imagehash

    IMAGEHASH_AVAILABLE = True
except Exception:
    IMAGEHASH_AVAILABLE = False


def file_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def perceptual_hash(path: str) -> Optional[str]:
    if not IMAGEHASH_AVAILABLE:
        return None
    try:
        img = Image.open(path)
        return str(imagehash.phash(img))
    except Exception:
        return None


def _hamming_distance(hex_hash_a: str, hex_hash_b: str) -> int:
    bits_a = bin(int(hex_hash_a, 16))[2:].zfill(len(hex_hash_a) * 4)
    bits_b = bin(int(hex_hash_b, 16))[2:].zfill(len(hex_hash_b) * 4)
    return sum(a != b for a, b in zip(bits_a, bits_b))


def compare_images(path_a: str, path_b: str) -> Dict[str, Any]:
    if not os.path.exists(path_a) or not os.path.exists(path_b):
        return {"success": False, "error": "image_not_found"}

    hash_a = perceptual_hash(path_a)
    hash_b = perceptual_hash(path_b)

    if hash_a and hash_b:
        dist = _hamming_distance(hash_a, hash_b)
        max_bits = len(hash_a) * 4
        similarity = max(0.0, 1.0 - (dist / max_bits))
        return {
            "success": True,
            "method": "phash",
            "hash_a": hash_a,
            "hash_b": hash_b,
            "distance": dist,
            "similarity": round(similarity, 4),
        }

    # 降级到文件级hash（仅能判断是否完全相同）
    sha_a = file_sha256(path_a)
    sha_b = file_sha256(path_b)
    return {
        "success": True,
        "method": "sha256_fallback",
        "hash_a": sha_a,
        "hash_b": sha_b,
        "distance": 0 if sha_a == sha_b else 1,
        "similarity": 1.0 if sha_a == sha_b else 0.0,
    }
