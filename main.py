"""
Серверная часть на Python (FastAPI). Заменяет две Supabase Edge Functions.

Делает то же самое, что и они:
- проверяет ECDSA-подпись (P-256) отправленного решения / голоса
- пишет в базу Supabase сервисным ключом (в обход RLS — только этот
  сервис имеет право писать в submissions/votes/chain_blocks)
- при голосовании сам пересчитывает итоги из базы и, если набралось
  большинство, сам чеканит блок с наградой

ВАЖНО про формат: браузер подписывает JSON.stringify(payload) как есть —
без пробелов, с кириллицей как есть (не экранированной). Poэтому здесь
обязательно json.dumps(..., ensure_ascii=False, separators=(",", ":")) —
иначе подписи не совпадут ни при каких обстоятельствах.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import Client, create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = FastAPI(title="coin-ledger backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # для продакшена лучше сузить до домена сайта
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- канонический JSON + криптография ----------

def canonical_json(payload: Dict[str, Any]) -> bytes:
    """Тот же побайтовый формат, что даёт JSON.stringify() в браузере."""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def js_number(x: Any) -> Any:
    """JS has one numeric type: Number(50.0) is just 50, and JSON.stringify(50)
    gives "50" — never "50.0". Postgres numeric/JSONB can round-trip a Python
    float as 50.0, which would hash differently from what the browser computes
    when it re-verifies the chain. Collapse whole numbers to int to match."""
    f = float(x)
    return int(f) if f.is_integer() else f


def hex_to_bytes(h: str) -> bytes:
    h = h[2:] if h.startswith("0x") else h
    return bytes.fromhex(h)


def verify_payload(address_hex: str, payload: Dict[str, Any], signature_hex: str) -> bool:
    """address — сырой публичный ключ (hex), signature — 64 байта r||s (формат Web Crypto)."""
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), hex_to_bytes(address_hex))
        sig_bytes = hex_to_bytes(signature_hex)
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der_sig = encode_dss_signature(r, s)
        public_key.verify(der_sig, canonical_json(payload), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False


# ---------- модели запросов ----------

class SubmitSolutionBody(BaseModel):
    taskId: str
    address: str
    text: str
    submittedAt: int
    signature: str


class CastVoteBody(BaseModel):
    taskId: str
    address: str
    approve: bool
    votedAt: int
    signature: str


# ---------- POST /submit-solution ----------

@app.post("/submit-solution")
def submit_solution(body: SubmitSolutionBody):
    payload = {
        "taskId": body.taskId,
        "address": body.address,
        "text": body.text,
        "submittedAt": body.submittedAt,
    }
    if not verify_payload(body.address, payload, body.signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    task_res = supabase.table("tasks").select("*").eq("id", body.taskId).single().execute()
    task = task_res.data
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] != "open":
        raise HTTPException(status_code=409, detail="Task is not open for submissions")

    participant_res = (
        supabase.table("project_participants")
        .select("address")
        .eq("project_id", task["project_id"])
        .eq("address", body.address)
        .maybe_single()
        .execute()
    )
    if not participant_res.data:
        raise HTTPException(status_code=403, detail="Address is not a project participant")

    supabase.table("submissions").update({"is_active": False}).eq("task_id", body.taskId).eq(
        "is_active", True
    ).execute()

    supabase.table("submissions").insert(
        {
            "task_id": body.taskId,
            "address": body.address,
            "text_body": body.text,
            "submitted_at": body.submittedAt,
            "signature": body.signature,
            "is_active": True,
        }
    ).execute()

    supabase.table("tasks").update({"status": "submitted"}).eq("id", body.taskId).execute()

    return {"ok": True}


# ---------- POST /cast-vote ----------

@app.post("/cast-vote")
def cast_vote(body: CastVoteBody):
    payload = {
        "taskId": body.taskId,
        "address": body.address,
        "approve": body.approve,
        "votedAt": body.votedAt,
    }
    if not verify_payload(body.address, payload, body.signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    task_res = supabase.table("tasks").select("*").eq("id", body.taskId).single().execute()
    task = task_res.data
    if not task or task["status"] != "submitted":
        raise HTTPException(status_code=409, detail="Task is not open for voting")

    submission_res = (
        supabase.table("submissions")
        .select("*")
        .eq("task_id", body.taskId)
        .eq("is_active", True)
        .maybe_single()
        .execute()
    )
    submission = submission_res.data
    if not submission:
        raise HTTPException(status_code=409, detail="No active submission")
    if submission["address"] == body.address:
        raise HTTPException(status_code=403, detail="Cannot vote on your own submission")

    participant_res = (
        supabase.table("project_participants")
        .select("address")
        .eq("project_id", task["project_id"])
        .eq("address", body.address)
        .maybe_single()
        .execute()
    )
    if not participant_res.data:
        raise HTTPException(status_code=403, detail="Not a project participant")

    existing_vote_res = (
        supabase.table("votes")
        .select("id")
        .eq("submission_id", submission["id"])
        .eq("address", body.address)
        .maybe_single()
        .execute()
    )
    if existing_vote_res.data:
        raise HTTPException(status_code=409, detail="Already voted")

    supabase.table("votes").insert(
        {
            "task_id": body.taskId,
            "submission_id": submission["id"],
            "address": body.address,
            "approve": body.approve,
            "voted_at": body.votedAt,
            "signature": body.signature,
        }
    ).execute()

    # источник истины для подсчёта — база данных, а не то, что прислал клиент
    participants_res = (
        supabase.table("project_participants").select("address").eq("project_id", task["project_id"]).execute()
    )
    participants: List[Dict[str, Any]] = participants_res.data or []
    eligible = len([p for p in participants if p["address"] != submission["address"]])

    all_votes_res = supabase.table("votes").select("*").eq("submission_id", submission["id"]).execute()
    all_votes: List[Dict[str, Any]] = all_votes_res.data or []
    votes_for = len([v for v in all_votes if v["approve"]])
    votes_against = len([v for v in all_votes if not v["approve"]])

    outcome = "pending"

    if eligible > 0 and votes_for > eligible / 2:
        outcome = "approved"

        last_block_res = (
            supabase.table("chain_blocks").select("*").order("index", desc=True).limit(1).maybe_single().execute()
        )
        last_block = last_block_res.data
        new_index = (last_block["index"] + 1) if last_block else 0
        previous_hash = last_block["hash"] if last_block else "0" * 64
        timestamp = int(time.time() * 1000)

        events = [
            {
                "type": "reward",
                "taskId": body.taskId,
                "projectId": task["project_id"],
                "to": submission["address"],
                "amount": js_number(task["reward"]),
                "submission": {
                    "taskId": body.taskId,
                    "address": submission["address"],
                    "text": submission["text_body"],
                    "submittedAt": submission["submitted_at"],
                    "signature": submission["signature"],
                },
                "votes": [
                    {
                        "taskId": body.taskId,
                        "address": v["address"],
                        "approve": v["approve"],
                        "votedAt": v["voted_at"],
                        "signature": v["signature"],
                    }
                    for v in all_votes
                ],
            }
        ]

        block_payload = {"index": new_index, "timestamp": timestamp, "previousHash": previous_hash, "events": events}
        block_hash = sha256_hex(canonical_json(block_payload))

        supabase.table("chain_blocks").insert(
            {
                "index": new_index,
                "timestamp": timestamp,
                "previous_hash": previous_hash,
                "hash": block_hash,
                "events": events,
            }
        ).execute()

        supabase.table("tasks").update({"status": "approved"}).eq("id", body.taskId).execute()

    elif eligible > 0 and votes_against > eligible / 2:
        outcome = "rejected"
        supabase.table("submissions").update({"is_active": False}).eq("id", submission["id"]).execute()
        supabase.table("tasks").update({"status": "open"}).eq("id", body.taskId).execute()

    return {"ok": True, "outcome": outcome, "votesFor": votes_for, "votesAgainst": votes_against, "eligible": eligible}


@app.get("/health")
def health():
    return {"status": "ok"}
