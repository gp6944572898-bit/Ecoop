// Supabase Edge Function: submit-solution
// Проверяет ECDSA-подпись решения и только после этого записывает его в базу
// сервисным ключом (в обход RLS). Прямая запись в submissions с anon-ключом
// запрещена — это единственный вход.

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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { taskId, address, text, submittedAt, signature } = await req.json();
    if (!taskId || !address || !text || !submittedAt || !signature) {
      return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers: corsHeaders });
    }

    // ключевой момент: именно этот порядок полей был подписан на клиенте
    const payload = { taskId, address, text, submittedAt };
    const validSig = await verifyPayload(address, payload, signature);
    if (!validSig) {
      return new Response(JSON.stringify({ error: "Invalid signature" }), { status: 401, headers: corsHeaders });
    }

    const supabase = createClient(Deno.env.get("SUPABASE_URL"), Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));

    const { data: task, error: taskErr } = await supabase.from("tasks").select("*").eq("id", taskId).single();
    if (taskErr || !task) {
      return new Response(JSON.stringify({ error: "Task not found" }), { status: 404, headers: corsHeaders });
    }
    if (task.status !== "open") {
      return new Response(JSON.stringify({ error: "Task is not open for submissions" }), { status: 409, headers: corsHeaders });
    }

    const { data: participant } = await supabase
      .from("project_participants")
      .select("address")
      .eq("project_id", task.project_id)
      .eq("address", address)
      .maybeSingle();
    if (!participant) {
      return new Response(JSON.stringify({ error: "Address is not a project participant" }), { status: 403, headers: corsHeaders });
    }

    await supabase.from("submissions").update({ is_active: false }).eq("task_id", taskId).eq("is_active", true);

    const { error: insertErr } = await supabase.from("submissions").insert({
      task_id: taskId,
      address,
      text_body: text,
      submitted_at: submittedAt,
      signature,
      is_active: true,
    });
    if (insertErr) throw insertErr;

    const { error: updateErr } = await supabase.from("tasks").update({ status: "submitted" }).eq("id", taskId);
    if (updateErr) throw updateErr;

    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: corsHeaders });
  }
});
