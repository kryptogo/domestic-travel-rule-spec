#!/usr/bin/env python3
"""Travel Rule API v2.2 — 認證簽章 reference sample（依 `spec/authentication.mdx`）

互通第一步：先確認雙方 HMAC-SHA256 簽章算法一致。本檔同時示範
**發送方產生簽章** 與 **接收方驗證簽章**，純標準庫（hmac/hashlib/secrets），
可逐行移植至任何語言。

用法（發送方自測，打對方 GET /health）:
    export TR_VASP_ID="kryptogo"
    export TR_SHARED_SECRET="公會分發的 pairwise secret"
    python3 tr_sign_sample.py https://sandbox-api.counterparty.com.tw/travel-rule/v1

已驗證：本腳本算出的 HMAC 與 `openssl dgst -sha256 -hmac` 對同一 message
結果完全一致，確保跨語言可重現。
"""
import sys
import os
import json
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

VASP_ID = os.environ.get("TR_VASP_ID", "kryptogo")
SHARED_SECRET = os.environ.get("TR_SHARED_SECRET", "")

# 接收方防重放：已用過的 nonce（正式環境請改用 Redis 等並保留 >= 24h）
_SEEN_NONCES: set[str] = set()
# 允許的時間誤差（秒），防重放
CLOCK_SKEW_SEC = 300


def iso_now() -> str:
    """ISO8601、UTC、秒級、帶 Z。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def gen_nonce() -> str:
    """32 字元隨機字串，作為 X-Nonce。"""
    return secrets.token_hex(16)


def _canonical_message(method: str, path: str, timestamp: str, nonce: str, body: str) -> str:
    """簽章輸入字串（規格定義）：

        "{method}\\n{path}\\n{timestamp}\\n{nonce}\\n{body_hash}"
        body_hash = SHA256(request_body)   # 無 body 時對空字串取 hash

    ⚠️ `path` 必須與請求 URL 的 path 逐字一致（含 `/travel-rule/v1` 前綴、
    不含 query string）。這是跨家對測最常見的不一致來源。
    """
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"


def sign(method: str, path: str, body: str, secret: str) -> dict:
    """發送方：產生 v2.2 認證 headers。"""
    ts = iso_now()
    nonce = gen_nonce()
    message = _canonical_message(method, path, ts, nonce, body)
    signature = hmac.new(secret.encode("utf-8"),
                         message.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    return {
        "X-VASP-ID": VASP_ID,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": signature,
        "Content-Type": "application/json",
    }


def verify(method: str, path: str, body: str, headers: dict, secret: str) -> tuple[bool, str]:
    """接收方：驗證簽章 + nonce + 時窗。回 (是否通過, 原因)。"""
    nonce = headers.get("X-Nonce", "")
    ts = headers.get("X-Timestamp", "")
    got_sig = headers.get("X-Signature", "")

    # 1) 防重放：nonce 不可重複（對應 409 DUPLICATE_NONCE）
    if nonce in _SEEN_NONCES:
        return False, "DUPLICATE_NONCE"

    # 2) 時窗檢查：timestamp 不可偏離太多
    try:
        sent = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if abs((datetime.now(timezone.utc) - sent).total_seconds()) > CLOCK_SKEW_SEC:
            return False, "TIMESTAMP_OUT_OF_RANGE"
    except ValueError:
        return False, "BAD_TIMESTAMP"

    # 3) 用同一把 shared_secret、相同 message 規則重算，常數時間比對
    message = _canonical_message(method, path, ts, nonce, body)
    want_sig = hmac.new(secret.encode("utf-8"),
                        message.encode("utf-8"),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(got_sig, want_sig):
        return False, "SIGNATURE_MISMATCH"

    _SEEN_NONCES.add(nonce)
    return True, "OK"


def main() -> None:
    if not SHARED_SECRET:
        print("⚠️  未設定 TR_SHARED_SECRET，以 DEMO_SECRET 示範簽章（無法實際通過對方驗章）\n")
    secret = SHARED_SECRET or "DEMO_SECRET"

    base = (sys.argv[1] if len(sys.argv) > 1
            else "https://sandbox-api.example.com/travel-rule/v1").rstrip("/")
    # 簽章用的 path 必須等於 URL 的 path
    path = "/travel-rule/v1/health"

    headers = sign("GET", path, "", secret)
    print("=== 發送方 headers ===")
    print(json.dumps(headers, indent=2, ensure_ascii=False))

    # 本機自我驗證：證明 sign/verify 對稱一致
    ok, reason = verify("GET", path, "", headers, secret)
    print(f"\n=== 接收方自我驗章（loopback）=== {ok} ({reason})")

    try:
        import requests
    except ImportError:
        print("\n（未安裝 requests，僅示範簽章；pip install requests 後可實際發送）")
        return

    url = base + "/health"
    print(f"\n=== GET {url} ===")
    try:
        r = requests.get(url, headers=headers, timeout=30)
        print(f"HTTP {r.status_code}\n{r.text[:500]}")
    except Exception as e:  # noqa: BLE001 — sample 容錯
        print(f"連線失敗：{e}")


if __name__ == "__main__":
    main()
