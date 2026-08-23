// Supabase Edge Function: cast-vote
// Проверяет ECDSA-подпись голоса, пересчитывает итоги ГОЛОСОВАНИЯ ИЗ БАЗЫ
// (а не из того, что прислал клиент), и сама чеканит блок с наградой, если
// набралось большинство. Клиент больше не может подделать одобрение —
// он может только прислать один подписанный голос за раз.

import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return bytes;
}

async function verifyPayload(addressHex, payload, signatureHex) {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(addressHex),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    const data = new TextEncoder().encode(JSON.stringify(payload));
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, hexToBytes(signatureHex), data);
  } catch (_e) {
    return false;
  }
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { taskId, address, approve, votedAt, signature } = await req.json();
    if (!taskId || !address || typeof approve !== "boolean" || !votedAt || !signature) {
      return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers: corsHeaders });
    }

    const payload = { taskId, address, approve, votedAt };
    const validSig = await verifyPayload(address, payload, signature);
    if (!validSig) {
      return new Response(JSON.stringify({ error: "Invalid signature" }), { status: 401, headers: corsHeaders });
    }

    const supabase = createClient(Deno.env.get("SUPABASE_URL"), Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));

    const { data: task } = await supabase.from("tasks").select("*").eq("id", taskId).single();
    if (!task || task.status !== "submitted") {
      return new Response(JSON.stringify({ error: "Task is not open for voting" }), { status: 409, headers: corsHeaders });
    }

    const { data: submission } = await supabase
      .from("submissions")
      .select("*")
      .eq("task_id", taskId)
      .eq("is_active", true)
      .maybeSingle();
    if (!submission) {
      return new Response(JSON.stringify({ error: "No active submission" }), { status: 409, headers: corsHeaders });
    }
    if (submission.address === address) {
      return new Response(JSON.stringify({ error: "Cannot vote on your own submission" }), { status: 403, headers: corsHeaders });
    }

    const { data: participant } = await supabase
      .from("project_participants")
      .select("address")
      .eq("project_id", task.project_id)
      .eq("address", address)
      .maybeSingle();
    if (!participant) {
      return new Response(JSON.stringify({ error: "Not a project participant" }), { status: 403, headers: corsHeaders });
    }

    const { data: existingVote } = await supabase
      .from("votes")
      .select("id")
      .eq("submission_id", submission.id)
      .eq("address", address)
      .maybeSingle();
    if (existingVote) {
      return new Response(JSON.stringify({ error: "Already voted" }), { status: 409, headers: corsHeaders });
    }

    const { error: voteInsertErr } = await supabase.from("votes").insert({
      task_id: taskId,
      submission_id: submission.id,
      address,
      approve,
      voted_at: votedAt,
      signature,
    });
    if (voteInsertErr) throw voteInsertErr;

    // источник истины для подсчёта — сама база, не то, что прислал клиент
    const { data: participants } = await supabase
      .from("project_participants")
      .select("address")
      .eq("project_id", task.project_id);
    const eligible = (participants || []).filter((p) => p.address !== submission.address).length;

    const { data: allVotes } = await supabase.from("votes").select("*").eq("submission_id", submission.id);
    const votesFor = (allVotes || []).filter((v) => v.approve).length;
    const votesAgainst = (allVotes || []).filter((v) => !v.approve).length;

    let outcome = "pending";

    if (eligible > 0 && votesFor > eligible / 2) {
      outcome = "approved";

      const { data: lastBlock } = await supabase
        .from("chain_blocks")
        .select("*")
        .order("index", { ascending: false })
        .limit(1)
        .maybeSingle();
      const newIndex = lastBlock ? lastBlock.index + 1 : 0;
      const previousHash = lastBlock ? lastBlock.hash : "0".repeat(64);
      const timestamp = Date.now();

      const events = [
        {
          type: "reward",
          taskId,
          projectId: task.project_id,
          to: submission.address,
          amount: Number(task.reward),
          submission: {
            taskId,
            address: submission.address,
            text: submission.text_body,
            submittedAt: submission.submitted_at,
            signature: submission.signature,
          },
          votes: (allVotes || []).map((v) => ({
            taskId,
            address: v.address,
            approve: v.approve,
            votedAt: v.voted_at,
            signature: v.signature,
          })),
        },
      ];

      const blockPayload = JSON.stringify({ index: newIndex, timestamp, previousHash, events });
      const hash = await sha256Hex(blockPayload);

      const { error: blockErr } = await supabase.from("chain_blocks").insert({
        index: newIndex,
        timestamp,
        previous_hash: previousHash,
        hash,
        events,
      });
      if (blockErr) throw blockErr;

      await supabase.from("tasks").update({ status: "approved" }).eq("id", taskId);
    } else if (eligible > 0 && votesAgainst > eligible / 2) {
      outcome = "rejected";
      await supabase.from("submissions").update({ is_active: false }).eq("id", submission.id);
      await supabase.from("tasks").update({ status: "open" }).eq("id", taskId);
    }

    return new Response(JSON.stringify({ ok: true, outcome, votesFor, votesAgainst, eligible }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: corsHeaders });
  }
});
