import React, { useState, useEffect, useMemo, useCallback } from "react";
import { supabase } from "./supabaseClient.js";
import {
  Wallet,
  Plus,
  Check,
  X,
  ChevronRight,
  ChevronLeft,
  Users,
  ListChecks,
  Link2,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Coins,
  CheckCircle2,
  Pencil,
  Trash2,
  History,
} from "lucide-react";

// ---------- palette / tokens (тёмная минималистичная тема) ----------
const COLORS = {
  bg: "#0E1621",
  surface: "#17212B",
  surfaceRaised: "#242F3D",
  border: "#2B3A48",
  text: "#FFFFFF",
  textDim: "#8B98A5",
  gold: "#2AABEE", // основной акцент — синий, как в Telegram
  goldDim: "#1C5F80",
  sage: "#4FAE4E",
  rust: "#E05353",
  ink: "#FFFFFF", // текст на акцентных кнопках — теперь белый (фон синий)
};

const FONTS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');
`;

// ---------- storage keys ----------
const K_IDENTITIES = "coin_ledger_identities"; // localStorage — never leaves this device

// ---------- identities: local to this browser/device only (private keys live here) ----------
function loadIdentities() {
  try {
    const raw = localStorage.getItem(K_IDENTITIES);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}
function saveIdentities(list) {
  try {
    localStorage.setItem(K_IDENTITIES, JSON.stringify(list));
    return true;
  } catch (e) {
    console.error("localStorage save failed", e);
    return false;
  }
}

// ---------- shared network state: read from Supabase tables, assembled into the
// same nested shape the UI expects (project.participants[], task.submission, task.votes[]) ----------
async function loadProjects() {
  const [{ data: projects, error: pErr }, { data: participants, error: qErr }] = await Promise.all([
    supabase.from("projects").select("id,title,description,created_by,created_at"),
    supabase.from("project_participants").select("project_id,address"),
  ]);
  if (pErr || qErr) {
    console.error("loadProjects failed", pErr, qErr);
    return [];
  }
  const byProject = {};
  (participants || []).forEach((p) => {
    (byProject[p.project_id] ||= []).push(p.address);
  });
  return (projects || []).map((p) => ({
    id: p.id,
    title: p.title,
    description: p.description || "",
    createdBy: p.created_by,
    createdAt: new Date(p.created_at).getTime(),
    participants: byProject[p.id] || [],
  }));
}

async function loadTasks() {
  const [{ data: tasks, error: tErr }, { data: submissions, error: sErr }, { data: votes, error: vErr }] =
    await Promise.all([
      supabase.from("tasks").select("id,project_id,title,description,reward,status,created_by,created_at"),
      supabase.from("submissions").select("*").eq("is_active", true),
      supabase.from("votes").select("*"),
    ]);
  if (tErr || sErr || vErr) {
    console.error("loadTasks failed", tErr, sErr, vErr);
    return [];
  }
  const subByTask = {};
  (submissions || []).forEach((s) => (subByTask[s.task_id] = s));
  const votesBySubmission = {};
  (votes || []).forEach((v) => (votesBySubmission[v.submission_id] ||= []).push(v));

  return (tasks || []).map((t) => {
    const sub = subByTask[t.id];
    return {
      id: t.id,
      projectId: t.project_id,
      title: t.title,
      description: t.description || "",
      reward: Number(t.reward),
      status: t.status,
      createdBy: t.created_by,
      createdAt: new Date(t.created_at).getTime(),
      submission: sub
        ? { taskId: t.id, address: sub.address, text: sub.text_body, submittedAt: sub.submitted_at, signature: sub.signature }
        : null,
      votes: sub
        ? (votesBySubmission[sub.id] || []).map((v) => ({
            taskId: t.id,
            address: v.address,
            approve: v.approve,
            votedAt: v.voted_at,
            signature: v.signature,
          }))
        : [],
    };
  });
}

async function loadChain() {
  const { data, error } = await supabase.from("chain_blocks").select("*").order("index", { ascending: true });
  if (error) {
    console.error("loadChain failed", error);
    return [];
  }
  return (data || []).map((b) => ({
    index: b.index,
    timestamp: b.timestamp,
    previousHash: b.previous_hash,
    hash: b.hash,
    events: b.events || [],
  }));
}

// ---------- activity log: best-effort audit trail, not security-critical ----------
async function loadActivityLog(projectId) {
  const { data, error } = await supabase
    .from("activity_log")
    .select("*")
    .eq("project_id", projectId)
    .order("created_at", { ascending: false })
    .limit(100);
  if (error) {
    console.error("loadActivityLog failed", error);
    return [];
  }
  return (data || []).map((r) => ({
    id: r.id,
    address: r.address,
    action: r.action,
    details: r.details || {},
    createdAt: new Date(r.created_at).getTime(),
  }));
}

async function logActivity(projectId, address, action, details) {
  try {
    await supabase.from("activity_log").insert({ project_id: projectId, address, action, details: details || {} });
  } catch (e) {
    console.error("logActivity failed", e);
  }
}

// ---------- crypto / hashing helpers ----------
async function sha256Hex(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBuf(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return bytes.buffer;
}

const EC_PARAMS = { name: "ECDSA", namedCurve: "P-256" };

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(EC_PARAMS, true, ["sign", "verify"]);
  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const address = "0x" + bufToHex(pubRaw);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  return { address, privateJwk };
}

async function importPrivateKey(jwk) {
  return crypto.subtle.importKey("jwk", jwk, EC_PARAMS, true, ["sign"]);
}
async function importPublicKeyFromAddress(address) {
  return crypto.subtle.importKey("raw", hexToBuf(address), EC_PARAMS, true, ["verify"]);
}

async function signPayload(privateJwk, payloadObj) {
  const key = await importPrivateKey(privateJwk);
  const data = new TextEncoder().encode(JSON.stringify(payloadObj));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data);
  return bufToHex(sig);
}

async function verifyPayload(address, payloadObj, signatureHex) {
  try {
    const key = await importPublicKeyFromAddress(address);
    const data = new TextEncoder().encode(JSON.stringify(payloadObj));
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, hexToBuf(signatureHex), data);
  } catch (e) {
    return false;
  }
}

function payloadOf(signed) {
  const { signature, ...payload } = signed;
  return payload;
}

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;

async function callBackend(path, body) {
  const res = await fetch(`${BACKEND_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.error || `${path} failed (${res.status})`);
  return data;
}

async function submitSolutionSecure({ taskId, address, text, submittedAt, signature }) {
  return callBackend("/submit-solution", { taskId, address, text, submittedAt, signature });
}

async function castVoteSecure({ taskId, address, approve, votedAt, signature }) {
  return callBackend("/cast-vote", { taskId, address, approve, votedAt, signature });
}

function shortAddr(addr) {
  if (!addr) return "";
  return addr.slice(0, 6) + "…" + addr.slice(-4);
}

function fmtTime(ts) {
  try {
    return new Date(ts).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" });
  } catch (e) {
    return "";
  }
}

async function blockHash(block) {
  const payload = JSON.stringify({
    index: block.index,
    timestamp: block.timestamp,
    previousHash: block.previousHash,
    events: block.events,
  });
  return sha256Hex(payload);
}

// ---------- small UI primitives ----------
function Sheet({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 50,
        display: "flex",
        flexDirection: "column",
        justifyContent: "flex-end",
      }}
    >
      <div
        onClick={onClose}
        style={{ position: "absolute", inset: 0, background: "rgba(4,7,14,0.6)" }}
      />
      <div
        style={{
          position: "relative",
          background: COLORS.surface,
          borderTop: `1px solid ${COLORS.border}`,
          borderTopLeftRadius: 20,
          borderTopRightRadius: 20,
          padding: "14px 18px 28px",
          maxHeight: "85vh",
          overflowY: "auto",
          animation: "slideUp 0.22s ease-out",
        }}
      >
        <div
          style={{
            width: 36,
            height: 4,
            background: COLORS.border,
            borderRadius: 999,
            margin: "0 auto 14px",
          }}
        />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <span style={{ fontFamily: "'Inter',sans-serif", fontWeight: 600, fontSize: 17, color: COLORS.text }}>
            {title}
          </span>
          <button onClick={onClose} style={iconBtnStyle}>
            <X size={18} color={COLORS.textDim} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

const iconBtnStyle = {
  background: "transparent",
  border: "none",
  padding: 6,
  borderRadius: 999,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
};

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 12, color: COLORS.textDim, marginBottom: 6, fontFamily: "'Roboto Mono',monospace" }}>
        {label}
      </div>
      {children}
    </div>
  );
}

const inputStyle = {
  width: "100%",
  background: COLORS.surfaceRaised,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 10,
  padding: "11px 12px",
  color: COLORS.text,
  fontSize: 15,
  fontFamily: "'Inter',sans-serif",
  outline: "none",
  boxSizing: "border-box",
};

function PrimaryButton({ children, onClick, disabled, style }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        width: "100%",
        background: disabled ? COLORS.goldDim : COLORS.gold,
        color: COLORS.ink,
        border: "none",
        borderRadius: 10,
        padding: "13px 16px",
        fontSize: 15,
        fontWeight: 600,
        fontFamily: "'Inter',sans-serif",
        opacity: disabled ? 0.6 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
        ...style,
      }}
    >
      {children}
    </button>
  );
}

function Badge({ status }) {
  const map = {
    open: { label: "Открыта", bg: "rgba(140,154,181,0.15)", color: COLORS.textDim },
    submitted: { label: "На голосовании", bg: "rgba(227,168,54,0.15)", color: COLORS.gold },
    approved: { label: "Принята", bg: "rgba(111,162,135,0.18)", color: COLORS.sage },
  };
  const s = map[status] || map.open;
  return (
    <span
      style={{
        background: s.bg,
        color: s.color,
        fontSize: 11,
        fontFamily: "'Roboto Mono',monospace",
        padding: "3px 8px",
        borderRadius: 999,
        letterSpacing: 0.3,
        whiteSpace: "nowrap",
      }}
    >
      {s.label}
    </span>
  );
}

// ---------- main app ----------
export default function App() {
  const [loading, setLoading] = useState(true);
  const [identities, setIdentities] = useState([]);
  const [activeAddress, setActiveAddress] = useState(null);
  const [projects, setProjects] = useState([]);
  const [tasks, setTasks] = useState([]);
  const [chain, setChain] = useState([]);

  const [tab, setTab] = useState("projects");
  const [screen, setScreen] = useState({ name: "list" }); // list | project | task
  const [identitySheetOpen, setIdentitySheetOpen] = useState(false);
  const [newIdentitySheet, setNewIdentitySheet] = useState(false);
  const [newProjectSheet, setNewProjectSheet] = useState(false);
  const [newTaskSheet, setNewTaskSheet] = useState(false);
  const [editTaskSheet, setEditTaskSheet] = useState(false);
  const [submitSheet, setSubmitSheet] = useState(false);
  const [editingTaskId, setEditingTaskId] = useState(null);

  const [nameInput, setNameInput] = useState("");
  const [titleInput, setTitleInput] = useState("");
  const [descInput, setDescInput] = useState("");
  const [rewardInput, setRewardInput] = useState("10");
  const [solutionInput, setSolutionInput] = useState("");

  const [verifyResult, setVerifyResult] = useState(null);
  const [activityLog, setActivityLog] = useState([]);

  // ---------- initial load + realtime ----------
  const refreshAll = useCallback(async () => {
    const [projs, tks, ch] = await Promise.all([loadProjects(), loadTasks(), loadChain()]);
    setProjects(projs);
    setTasks(tks);
    setChain(ch);
  }, []);

  useEffect(() => {
    (async () => {
      const ids = loadIdentities();
      setIdentities(ids);
      setActiveAddress(ids.length ? ids[0].address : null);
      await refreshAll();
      setLoading(false);
    })();

    // live updates: reflect what other visitors do, in real time
    const channel = supabase
      .channel("public_tables")
      .on("postgres_changes", { event: "*", schema: "public", table: "projects" }, refreshAll)
      .on("postgres_changes", { event: "*", schema: "public", table: "project_participants" }, refreshAll)
      .on("postgres_changes", { event: "*", schema: "public", table: "tasks" }, refreshAll)
      .on("postgres_changes", { event: "*", schema: "public", table: "submissions" }, refreshAll)
      .on("postgres_changes", { event: "*", schema: "public", table: "votes" }, refreshAll)
      .on("postgres_changes", { event: "*", schema: "public", table: "chain_blocks" }, refreshAll)
      .on("postgres_changes", { event: "*", schema: "public", table: "activity_log" }, () => {
        setScreen((s) => {
          if (s.name !== "list") loadActivityLog(s.projectId).then(setActivityLog);
          return s;
        });
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [refreshAll]);

  // load the activity log whenever a project is opened
  useEffect(() => {
    if (screen.name !== "list" && screen.projectId) {
      loadActivityLog(screen.projectId).then(setActivityLog);
    } else {
      setActivityLog([]);
    }
  }, [screen.name, screen.projectId]);


  // ---------- balances ----------
  const balances = useMemo(() => {
    const map = {};
    chain.forEach((b) =>
      (b.events || []).forEach((e) => {
        if (e.type === "reward") map[e.to] = (map[e.to] || 0) + e.amount;
      })
    );
    return map;
  }, [chain]);

  const activeIdentity = identities.find((i) => i.address === activeAddress) || null;
  const activeBalance = activeAddress ? balances[activeAddress] || 0 : 0;

  // ---------- identity actions ----------
  const createIdentity = useCallback(async () => {
    const name = nameInput.trim() || `Участник ${identities.length + 1}`;
    const { address, privateJwk } = await generateKeyPair();
    const next = [...identities, { address, name, createdAt: Date.now(), privateJwk }];
    setIdentities(next);
    saveIdentities(next);
    setActiveAddress(address);
    setNameInput("");
    setNewIdentitySheet(false);
  }, [nameInput, identities]);

  // ---------- project actions ----------
  const createProject = useCallback(async () => {
    if (!activeAddress || !titleInput.trim()) return;
    const { data: inserted, error } = await supabase
      .from("projects")
      .insert({ title: titleInput.trim(), description: descInput.trim(), created_by: activeAddress })
      .select()
      .single();
    if (error) {
      console.error("createProject failed", error);
      return;
    }
    await supabase.from("project_participants").insert({ project_id: inserted.id, address: activeAddress });
    logActivity(inserted.id, activeAddress, "project_created", { title: inserted.title });
    await refreshAll();
    setTitleInput("");
    setDescInput("");
    setNewProjectSheet(false);
  }, [activeAddress, titleInput, descInput, refreshAll]);

  const joinProject = useCallback(
    async (projectId) => {
      if (!activeAddress) return;
      const { error } = await supabase
        .from("project_participants")
        .insert({ project_id: projectId, address: activeAddress });
      if (error && error.code !== "23505") {
        console.error("joinProject failed", error);
        return;
      }
      if (!error) logActivity(projectId, activeAddress, "joined_project", {});
      await refreshAll();
    },
    [activeAddress, refreshAll]
  );

  // ---------- task actions ----------
  const createTask = useCallback(async () => {
    if (!activeAddress || !titleInput.trim() || screen.name !== "project") return;
    const reward = Math.max(1, Number(rewardInput) || 0);
    const { error } = await supabase.from("tasks").insert({
      project_id: screen.projectId,
      title: titleInput.trim(),
      description: descInput.trim(),
      reward,
      created_by: activeAddress,
    });
    if (error) {
      console.error("createTask failed", error);
      return;
    }
    logActivity(screen.projectId, activeAddress, "task_created", { title: titleInput.trim() });
    await refreshAll();
    setTitleInput("");
    setDescInput("");
    setRewardInput("10");
    setNewTaskSheet(false);
  }, [activeAddress, titleInput, descInput, rewardInput, screen, refreshAll]);

  const openEditTask = useCallback((task) => {
    setEditingTaskId(task.id);
    setTitleInput(task.title);
    setDescInput(task.description);
    setRewardInput(String(task.reward));
    setEditTaskSheet(true);
  }, []);

  const updateTask = useCallback(async () => {
    if (!editingTaskId || !titleInput.trim() || screen.name !== "project") return;
    const reward = Math.max(1, Number(rewardInput) || 0);
    const { error } = await supabase
      .from("tasks")
      .update({ title: titleInput.trim(), description: descInput.trim(), reward })
      .eq("id", editingTaskId)
      .eq("status", "open");
    if (error) {
      console.error("updateTask failed", error);
      alert("Не удалось изменить задачу: " + error.message);
      return;
    }
    logActivity(screen.projectId, activeAddress, "task_edited", { title: titleInput.trim() });
    await refreshAll();
    setTitleInput("");
    setDescInput("");
    setRewardInput("10");
    setEditingTaskId(null);
    setEditTaskSheet(false);
  }, [editingTaskId, titleInput, descInput, rewardInput, screen, activeAddress, refreshAll]);

  const deleteTask = useCallback(
    async (task) => {
      if (!window.confirm(`Удалить задачу «${task.title}»? Это необратимо.`)) return;
      const { error } = await supabase.from("tasks").delete().eq("id", task.id).eq("status", "open");
      if (error) {
        console.error("deleteTask failed", error);
        alert("Не удалось удалить задачу: " + error.message);
        return;
      }
      logActivity(task.projectId, activeAddress, "task_deleted", { title: task.title });
      await refreshAll();
      setScreen({ name: "project", projectId: task.projectId });
    },
    [activeAddress, refreshAll]
  );

  const submitSolution = useCallback(
    async (taskId) => {
      if (!activeAddress || !solutionInput.trim()) return;
      const identity = identities.find((i) => i.address === activeAddress);
      if (!identity) return;
      const task = tasks.find((t) => t.id === taskId);
      const payload = {
        taskId,
        address: activeAddress,
        text: solutionInput.trim(),
        submittedAt: Date.now(),
      };
      const signature = await signPayload(identity.privateJwk, payload);
      try {
        await submitSolutionSecure({ ...payload, signature });
        if (task) logActivity(task.projectId, activeAddress, "solution_submitted", { title: task.title });
        await refreshAll();
      } catch (e) {
        console.error("submitSolution failed", e);
        alert("Не удалось отправить решение: " + e.message);
        return;
      }
      setSolutionInput("");
      setSubmitSheet(false);
    },
    [activeAddress, solutionInput, identities, tasks, refreshAll]
  );

  const castVote = useCallback(
    async (taskId, approve) => {
      const task = tasks.find((t) => t.id === taskId);
      if (!task || task.status !== "submitted" || !activeAddress) return;
      if (task.submission.address === activeAddress) return;
      if (task.votes.some((v) => v.address === activeAddress)) return;
      const identity = identities.find((i) => i.address === activeAddress);
      if (!identity) return;

      const votePayload = { taskId, address: activeAddress, approve, votedAt: Date.now() };
      const signature = await signPayload(identity.privateJwk, votePayload);
      try {
        await castVoteSecure({ ...votePayload, signature });
        logActivity(task.projectId, activeAddress, "voted", { title: task.title, approve });
        await refreshAll();
      } catch (e) {
        console.error("castVote failed", e);
        alert("Не удалось учесть голос: " + e.message);
      }
    },
    [tasks, activeAddress, identities, refreshAll]
  );

  const verifyChain = useCallback(async () => {
    for (let i = 0; i < chain.length; i++) {
      const b = chain[i];
      const recomputed = await blockHash(b);
      if (recomputed !== b.hash) {
        setVerifyResult({ valid: false, at: i, reason: "хэш блока не совпадает" });
        return;
      }
      if (i > 0 && b.previousHash !== chain[i - 1].hash) {
        setVerifyResult({ valid: false, at: i, reason: "разрыв цепочки хэшей" });
        return;
      }
      for (const e of b.events || []) {
        if (e.type !== "reward") continue;
        if (e.submission && e.submission.signature) {
          const ok = await verifyPayload(e.submission.address, payloadOf(e.submission), e.submission.signature);
          if (!ok) {
            setVerifyResult({ valid: false, at: i, reason: "неверная подпись решения" });
            return;
          }
        }
        for (const v of e.votes || []) {
          if (!v.signature) continue;
          const ok = await verifyPayload(v.address, payloadOf(v), v.signature);
          if (!ok) {
            setVerifyResult({ valid: false, at: i, reason: "неверная подпись голоса" });
            return;
          }
        }
      }
    }
    setVerifyResult({ valid: true });
  }, [chain]);

  // ---------- derived screen data ----------
  const currentProject = screen.name !== "list" ? projects.find((p) => p.id === screen.projectId) : null;
  const projectTasks = currentProject ? tasks.filter((t) => t.projectId === currentProject.id) : [];
  const currentTask = screen.name === "task" ? tasks.find((t) => t.id === screen.taskId) : null;

  if (loading) {
    return (
      <div style={{ ...appShellStyle, alignItems: "center", justifyContent: "center" }}>
        <style>{FONTS}</style>
        <span style={{ color: COLORS.textDim, fontFamily: "'Roboto Mono',monospace", fontSize: 13 }}>
          загрузка реестра…
        </span>
      </div>
    );
  }

  return (
    <div style={appShellStyle}>
      <style>{`
        ${FONTS}
        * { box-sizing: border-box; }
        body { margin: 0; }
        ::placeholder { color: ${COLORS.textDim}; opacity: 0.7; }
        @keyframes slideUp { from { transform: translateY(24px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>

      {/* top bar */}
      <div
        style={{
          padding: "16px 18px 12px",
          borderBottom: `1px solid ${COLORS.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <div>
          <div style={{ fontFamily: "'Inter',sans-serif", fontWeight: 700, fontSize: 18, color: COLORS.text, letterSpacing: -0.3 }}>
            Реестр вклада
          </div>
          <div style={{ fontFamily: "'Roboto Mono',monospace", fontSize: 11, color: COLORS.textDim }}>
            монеты — за выполненные задачи
          </div>
        </div>
        <button
          onClick={() => setIdentitySheetOpen(true)}
          style={{
            background: COLORS.surfaceRaised,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 12,
            padding: "8px 12px",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          {activeIdentity ? (
            <>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 12, color: COLORS.text, fontFamily: "'Inter',sans-serif", fontWeight: 600 }}>
                  {activeIdentity.name}
                </div>
                <div style={{ fontSize: 11, color: COLORS.gold, fontFamily: "'Roboto Mono',monospace" }}>
                  {activeBalance} монет
                </div>
              </div>
              <Wallet size={18} color={COLORS.gold} />
            </>
          ) : (
            <span style={{ fontSize: 12, color: COLORS.gold, fontFamily: "'Inter',sans-serif" }}>Создать личность</span>
          )}
        </button>
      </div>

      {/* body */}
      <div style={{ flex: 1, overflowY: "auto", padding: "14px 18px 90px" }}>
        {tab === "wallet" && (
          <WalletTab
            identities={identities}
            balances={balances}
            activeAddress={activeAddress}
            setActiveAddress={setActiveAddress}
            onNewIdentity={() => setNewIdentitySheet(true)}
          />
        )}

        {tab === "projects" && screen.name === "list" && (
          <ProjectsList
            projects={projects}
            tasks={tasks}
            onOpen={(id) => setScreen({ name: "project", projectId: id })}
            onNew={() => setNewProjectSheet(true)}
            hasIdentity={!!activeAddress}
          />
        )}

        {tab === "projects" && screen.name === "project" && currentProject && (
          <ProjectDetail
            project={currentProject}
            tasksList={projectTasks}
            activeAddress={activeAddress}
            identities={identities}
            activityLog={activityLog}
            onBack={() => setScreen({ name: "list" })}
            onJoin={() => joinProject(currentProject.id)}
            onNewTask={() => setNewTaskSheet(true)}
            onOpenTask={(id) => setScreen({ name: "task", projectId: currentProject.id, taskId: id })}
          />
        )}

        {tab === "projects" && screen.name === "task" && currentTask && currentProject && (
          <TaskDetail
            task={currentTask}
            project={currentProject}
            identities={identities}
            activeAddress={activeAddress}
            onBack={() => setScreen({ name: "project", projectId: currentProject.id })}
            onSubmit={() => setSubmitSheet(true)}
            onVote={(approve) => castVote(currentTask.id, approve)}
            onEdit={() => openEditTask(currentTask)}
            onDelete={() => deleteTask(currentTask)}
          />
        )}

        {tab === "chain" && (
          <ChainTab chain={chain} tasks={tasks} identities={identities} onVerify={verifyChain} verifyResult={verifyResult} />
        )}
      </div>

      {/* tab bar */}
      <div
        style={{
          position: "fixed",
          bottom: 0,
          left: 0,
          right: 0,
          background: COLORS.surface,
          borderTop: `1px solid ${COLORS.border}`,
          display: "flex",
          padding: "8px 10px calc(8px + env(safe-area-inset-bottom))",
        }}
      >
        {[
          { key: "wallet", label: "Кошелёк", icon: Wallet },
          { key: "projects", label: "Проекты", icon: ListChecks },
          { key: "chain", label: "Реестр", icon: Link2 },
        ].map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => {
              setTab(key);
              if (key !== "projects") setScreen({ name: "list" });
            }}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 3,
              padding: "6px 0",
            }}
          >
            <Icon size={20} color={tab === key ? COLORS.gold : COLORS.textDim} />
            <span
              style={{
                fontSize: 11,
                fontFamily: "'Roboto Mono',monospace",
                color: tab === key ? COLORS.gold : COLORS.textDim,
              }}
            >
              {label}
            </span>
          </button>
        ))}
      </div>

      {/* identity switcher sheet */}
      <Sheet open={identitySheetOpen} onClose={() => setIdentitySheetOpen(false)} title="Личности на этом устройстве">
        {identities.length === 0 && (
          <div style={{ color: COLORS.textDim, fontSize: 13, marginBottom: 14 }}>
            Ещё нет ни одной личности. Создай первую, чтобы участвовать в проектах.
          </div>
        )}
        {identities.map((id) => (
          <button
            key={id.address}
            onClick={() => {
              setActiveAddress(id.address);
              setIdentitySheetOpen(false);
            }}
            style={{
              width: "100%",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              background: id.address === activeAddress ? "rgba(227,168,54,0.1)" : "transparent",
              border: `1px solid ${id.address === activeAddress ? COLORS.gold : COLORS.border}`,
              borderRadius: 10,
              padding: "10px 12px",
              marginBottom: 8,
            }}
          >
            <div style={{ textAlign: "left" }}>
              <div style={{ color: COLORS.text, fontFamily: "'Inter',sans-serif", fontWeight: 600, fontSize: 14 }}>
                {id.name}
              </div>
              <div style={{ color: COLORS.textDim, fontFamily: "'Roboto Mono',monospace", fontSize: 11 }}>
                {shortAddr(id.address)} · {balances[id.address] || 0} монет
              </div>
            </div>
            {id.address === activeAddress && <Check size={16} color={COLORS.gold} />}
          </button>
        ))}
        <div style={{ marginTop: 8 }}>
          <PrimaryButton
            onClick={() => {
              setIdentitySheetOpen(false);
              setNewIdentitySheet(true);
            }}
          >
            + Новая личность
          </PrimaryButton>
        </div>
        <div style={{ color: COLORS.textDim, fontSize: 11, marginTop: 12, lineHeight: 1.5 }}>
          Совет: создай 2–3 личности, чтобы протестировать голосование за выполненные задачи — один участник
          отправляет решение, другие подтверждают.
        </div>
      </Sheet>

      {/* new identity sheet */}
      <Sheet open={newIdentitySheet} onClose={() => setNewIdentitySheet(false)} title="Новая личность">
        <Field label="имя (только для этого устройства)">
          <input
            style={inputStyle}
            value={nameInput}
            onChange={(e) => setNameInput(e.target.value)}
            placeholder="например, Аня"
            autoFocus
          />
        </Field>
        <PrimaryButton onClick={createIdentity}>Создать</PrimaryButton>
      </Sheet>

      {/* new project sheet */}
      <Sheet open={newProjectSheet} onClose={() => setNewProjectSheet(false)} title="Новый проект">
        <Field label="название">
          <input style={inputStyle} value={titleInput} onChange={(e) => setTitleInput(e.target.value)} placeholder="Название проекта" />
        </Field>
        <Field label="описание">
          <textarea
            style={{ ...inputStyle, minHeight: 80, resize: "vertical" }}
            value={descInput}
            onChange={(e) => setDescInput(e.target.value)}
            placeholder="О чём проект"
          />
        </Field>
        <PrimaryButton onClick={createProject} disabled={!titleInput.trim() || !activeAddress}>
          Создать проект
        </PrimaryButton>
      </Sheet>

      {/* new task sheet */}
      <Sheet open={newTaskSheet} onClose={() => setNewTaskSheet(false)} title="Новая задача">
        <Field label="название">
          <input style={inputStyle} value={titleInput} onChange={(e) => setTitleInput(e.target.value)} placeholder="Что нужно сделать" />
        </Field>
        <Field label="описание">
          <textarea
            style={{ ...inputStyle, minHeight: 70, resize: "vertical" }}
            value={descInput}
            onChange={(e) => setDescInput(e.target.value)}
            placeholder="Подробности задачи"
          />
        </Field>
        <Field label="награда, монет">
          <input
            style={inputStyle}
            type="number"
            min="1"
            value={rewardInput}
            onChange={(e) => setRewardInput(e.target.value)}
          />
        </Field>
        <PrimaryButton onClick={createTask} disabled={!titleInput.trim()}>
          Добавить задачу
        </PrimaryButton>
      </Sheet>

      {/* edit task sheet */}
      <Sheet
        open={editTaskSheet}
        onClose={() => {
          setEditTaskSheet(false);
          setEditingTaskId(null);
        }}
        title="Изменить задачу"
      >
        <Field label="название">
          <input style={inputStyle} value={titleInput} onChange={(e) => setTitleInput(e.target.value)} placeholder="Что нужно сделать" />
        </Field>
        <Field label="описание">
          <textarea
            style={{ ...inputStyle, minHeight: 70, resize: "vertical" }}
            value={descInput}
            onChange={(e) => setDescInput(e.target.value)}
            placeholder="Подробности задачи"
          />
        </Field>
        <Field label="награда, монет">
          <input
            style={inputStyle}
            type="number"
            min="1"
            value={rewardInput}
            onChange={(e) => setRewardInput(e.target.value)}
          />
        </Field>
        <PrimaryButton onClick={updateTask} disabled={!titleInput.trim()}>
          Сохранить изменения
        </PrimaryButton>
      </Sheet>

      {/* submit solution sheet */}
      <Sheet open={submitSheet} onClose={() => setSubmitSheet(false)} title="Отправить решение">
        <Field label="что сделано / ссылка / описание результата">
          <textarea
            style={{ ...inputStyle, minHeight: 100, resize: "vertical" }}
            value={solutionInput}
            onChange={(e) => setSolutionInput(e.target.value)}
            placeholder="Опиши результат — участники проекта проголосуют"
            autoFocus
          />
        </Field>
        <PrimaryButton onClick={() => currentTask && submitSolution(currentTask.id)} disabled={!solutionInput.trim()}>
          Отправить на голосование
        </PrimaryButton>
      </Sheet>
    </div>
  );
}

const appShellStyle = {
  display: "flex",
  flexDirection: "column",
  height: "100vh",
  width: "100%",
  background: COLORS.bg,
  color: COLORS.text,
  fontFamily: "'Inter',sans-serif",
};

// ---------- Wallet tab ----------
function WalletTab({ identities, balances, activeAddress, setActiveAddress, onNewIdentity }) {
  return (
    <div>
      <SectionTitle>Личности на устройстве</SectionTitle>
      {identities.length === 0 && (
        <EmptyState
          icon={Wallet}
          text="Пока нет ни одной личности. Создай первую — она станет твоим адресом для наград."
        />
      )}
      {identities.map((id) => (
        <div
          key={id.address}
          onClick={() => setActiveAddress(id.address)}
          style={{
            ...cardStyle,
            borderColor: id.address === activeAddress ? COLORS.gold : COLORS.border,
            marginBottom: 10,
            cursor: "pointer",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: 15 }}>{id.name}</div>
              <div style={{ fontFamily: "'Roboto Mono',monospace", fontSize: 11, color: COLORS.textDim, marginTop: 2 }}>
                {shortAddr(id.address)}
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ color: COLORS.gold, fontFamily: "'Roboto Mono',monospace", fontWeight: 600, fontSize: 16 }}>
                {balances[id.address] || 0}
              </div>
              <div style={{ fontSize: 10, color: COLORS.textDim }}>монет</div>
            </div>
          </div>
        </div>
      ))}
      <div style={{ marginTop: 16 }}>
        <PrimaryButton onClick={onNewIdentity}>
          <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
            <Plus size={16} /> Новая личность
          </span>
        </PrimaryButton>
      </div>
    </div>
  );
}

// ---------- Projects list ----------
function ProjectsList({ projects, tasks, onOpen, onNew, hasIdentity }) {
  return (
    <div>
      <SectionTitle>Проекты</SectionTitle>
      {projects.length === 0 && (
        <EmptyState icon={ListChecks} text="Проектов ещё нет. Создай первый и добавь в него задачи с наградой." />
      )}
      {projects.map((p) => {
        const pTasks = tasks.filter((t) => t.projectId === p.id);
        const approved = pTasks.filter((t) => t.status === "approved").length;
        return (
          <div key={p.id} onClick={() => onOpen(p.id)} style={{ ...cardStyle, marginBottom: 10, cursor: "pointer" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 15 }}>{p.title}</div>
                {p.description && (
                  <div style={{ color: COLORS.textDim, fontSize: 12.5, marginTop: 3, lineHeight: 1.4 }}>{p.description}</div>
                )}
                <div style={{ display: "flex", gap: 12, marginTop: 8 }}>
                  <MiniStat icon={Users} value={p.participants.length} />
                  <MiniStat icon={ListChecks} value={`${approved}/${pTasks.length}`} />
                </div>
              </div>
              <ChevronRight size={18} color={COLORS.textDim} />
            </div>
          </div>
        );
      })}
      <div style={{ marginTop: 16 }}>
        <PrimaryButton onClick={onNew} disabled={!hasIdentity}>
          <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
            <Plus size={16} /> Новый проект
          </span>
        </PrimaryButton>
        {!hasIdentity && (
          <div style={{ color: COLORS.textDim, fontSize: 11, marginTop: 8, textAlign: "center" }}>
            Сначала создай личность на вкладке «Кошелёк»
          </div>
        )}
      </div>
    </div>
  );
}

function MiniStat({ icon: Icon, value }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 4, color: COLORS.textDim, fontSize: 12, fontFamily: "'Roboto Mono',monospace" }}>
      <Icon size={13} /> {value}
    </span>
  );
}

// ---------- Project detail ----------
function ProjectDetail({ project, tasksList, activeAddress, identities, activityLog, onBack, onJoin, onNewTask, onOpenTask }) {
  const isParticipant = activeAddress && project.participants.includes(activeAddress);
  const nameFor = (addr) => identities.find((i) => i.address === addr)?.name || shortAddr(addr);

  const actionLabel = (entry) => {
    const d = entry.details || {};
    switch (entry.action) {
      case "project_created":
        return "создал(а) проект";
      case "joined_project":
        return "присоединился(ась) к проекту";
      case "task_created":
        return `добавил(а) задачу «${d.title}»`;
      case "task_edited":
        return `изменил(а) задачу «${d.title}»`;
      case "task_deleted":
        return `удалил(а) задачу «${d.title}»`;
      case "solution_submitted":
        return `отправил(а) решение по «${d.title}»`;
      case "voted":
        return `проголосовал(а) ${d.approve ? "«за»" : "«против»"} по «${d.title}»`;
      default:
        return entry.action;
    }
  };

  return (
    <div>
      <BackRow onBack={onBack} label="Проекты" />
      <div style={{ fontSize: 19, fontWeight: 700, marginTop: 6 }}>{project.title}</div>
      {project.description && <div style={{ color: COLORS.textDim, fontSize: 13.5, marginTop: 4, lineHeight: 1.5 }}>{project.description}</div>}

      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 12 }}>
        {project.participants.map((a) => (
          <span
            key={a}
            style={{
              background: COLORS.surfaceRaised,
              border: `1px solid ${COLORS.border}`,
              borderRadius: 999,
              padding: "4px 10px",
              fontSize: 11.5,
              fontFamily: "'Roboto Mono',monospace",
              color: COLORS.textDim,
            }}
          >
            {nameFor(a)}
          </span>
        ))}
      </div>

      {!isParticipant && activeAddress && (
        <div style={{ marginTop: 14 }}>
          <PrimaryButton onClick={onJoin}>Присоединиться к проекту</PrimaryButton>
        </div>
      )}

      <div style={{ marginTop: 22 }}>
        <SectionTitle>Задачи</SectionTitle>
        {tasksList.length === 0 && <EmptyState icon={ListChecks} text="Задач пока нет." />}
        {tasksList.map((t) => (
          <div key={t.id} onClick={() => onOpenTask(t.id)} style={{ ...cardStyle, marginBottom: 10, cursor: "pointer" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 14.5 }}>{t.title}</div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                  <Badge status={t.status} />
                  <span style={{ display: "flex", alignItems: "center", gap: 3, color: COLORS.gold, fontFamily: "'Roboto Mono',monospace", fontSize: 12 }}>
                    <Coins size={12} /> {t.reward}
                  </span>
                </div>
              </div>
              <ChevronRight size={17} color={COLORS.textDim} />
            </div>
          </div>
        ))}
        {isParticipant && (
          <PrimaryButton onClick={onNewTask} style={{ marginTop: 6 }}>
            <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
              <Plus size={16} /> Добавить задачу
            </span>
          </PrimaryButton>
        )}
      </div>

      {activityLog.length > 0 && (
        <div style={{ marginTop: 26 }}>
          <SectionTitle>
            <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <History size={12} /> Журнал действий
            </span>
          </SectionTitle>
          {activityLog.map((entry) => (
            <div key={entry.id} style={{ display: "flex", gap: 8, marginBottom: 10, fontSize: 12.5 }}>
              <div style={{ color: COLORS.textDim, fontFamily: "'Roboto Mono',monospace", flexShrink: 0, minWidth: 44 }}>
                {fmtTime(entry.createdAt).split(",")[1]?.trim() || fmtTime(entry.createdAt)}
              </div>
              <div style={{ color: COLORS.text }}>
                <span style={{ fontWeight: 600 }}>{nameFor(entry.address)}</span>{" "}
                <span style={{ color: COLORS.textDim }}>{actionLabel(entry)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------- Task detail ----------
function TaskDetail({ task, project, identities, activeAddress, onBack, onSubmit, onVote, onEdit, onDelete }) {
  const isParticipant = activeAddress && project.participants.includes(activeAddress);
  const isOwner = activeAddress && task.createdBy === activeAddress;
  const nameFor = (addr) => identities.find((i) => i.address === addr)?.name || shortAddr(addr);
  const alreadyVoted = task.votes.find((v) => v.address === activeAddress);
  const isSubmitter = task.submission && task.submission.address === activeAddress;
  const eligible = task.submission ? project.participants.filter((a) => a !== task.submission.address).length : 0;
  const votesFor = task.votes.filter((v) => v.approve).length;
  const votesAgainst = task.votes.filter((v) => !v.approve).length;

  const [sigValid, setSigValid] = useState({});
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const results = {};
      if (task.submission && task.submission.signature) {
        results["submission:" + task.submission.address] = await verifyPayload(
          task.submission.address,
          payloadOf(task.submission),
          task.submission.signature
        );
      }
      for (const v of task.votes) {
        if (!v.signature) continue;
        results["vote:" + v.address] = await verifyPayload(v.address, payloadOf(v), v.signature);
      }
      if (!cancelled) setSigValid(results);
    })();
    return () => {
      cancelled = true;
    };
  }, [task.submission, task.votes]);

  return (
    <div>
      <BackRow onBack={onBack} label={project.title} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginTop: 6 }}>
        <div style={{ fontSize: 18, fontWeight: 700, flex: 1 }}>{task.title}</div>
        <Badge status={task.status} />
      </div>
      {task.description && <div style={{ color: COLORS.textDim, fontSize: 13.5, marginTop: 6, lineHeight: 1.5 }}>{task.description}</div>}
      <div style={{ display: "flex", alignItems: "center", gap: 4, marginTop: 10, color: COLORS.gold, fontFamily: "'Roboto Mono',monospace", fontSize: 13 }}>
        <Coins size={14} /> награда: {task.reward} монет
      </div>

      {isOwner && task.status === "open" && (
        <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
          <button onClick={onEdit} style={iconTextBtnStyle}>
            <Pencil size={14} /> Изменить
          </button>
          <button onClick={onDelete} style={{ ...iconTextBtnStyle, color: COLORS.rust }}>
            <Trash2 size={14} /> Удалить
          </button>
        </div>
      )}

      {task.status === "approved" && (
        <div
          style={{
            marginTop: 18,
            background: "rgba(79,174,78,0.12)",
            borderRadius: 12,
            padding: "14px 16px",
            display: "flex",
            alignItems: "flex-start",
            gap: 10,
            animation: "fadeInUp 0.25s ease-out",
          }}
        >
          <CheckCircle2 size={18} color={COLORS.sage} style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <div style={{ color: COLORS.sage, fontWeight: 600, fontFamily: "'Inter',sans-serif", fontSize: 14 }}>
              Принято голосованием
            </div>
            <div style={{ color: COLORS.textDim, fontSize: 12, marginTop: 2 }}>
              {nameFor(task.submission.address)} получил(а) {task.reward} монет
            </div>
          </div>
        </div>
      )}

      {task.status === "open" && isParticipant && (
        <div style={{ marginTop: 18 }}>
          <PrimaryButton onClick={onSubmit}>Отправить решение</PrimaryButton>
        </div>
      )}
      {task.status === "open" && !isParticipant && (
        <div style={{ color: COLORS.textDim, fontSize: 12, marginTop: 14 }}>
          Присоединись к проекту, чтобы отправить решение.
        </div>
      )}

      {task.status === "submitted" && task.submission && (
        <div style={{ marginTop: 18 }}>
          <div
            style={{
              fontSize: 12,
              color: COLORS.textDim,
              fontFamily: "'Roboto Mono',monospace",
              marginBottom: 6,
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            решение от {nameFor(task.submission.address)} · {fmtTime(task.submission.submittedAt)}
            <SigBadge valid={sigValid["submission:" + task.submission.address]} />
          </div>
          <div style={{ ...cardStyle, background: COLORS.surfaceRaised }}>{task.submission.text}</div>

          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16, marginBottom: 10 }}>
            <span style={{ fontSize: 12, color: COLORS.textDim, fontFamily: "'Roboto Mono',monospace" }}>
              голоса: {votesFor} за / {votesAgainst} против · нужно больше половины из {eligible}
            </span>
          </div>

          {task.votes.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
              {task.votes.map((v) => (
                <span
                  key={v.address}
                  style={{
                    fontSize: 11,
                    fontFamily: "'Roboto Mono',monospace",
                    padding: "3px 8px",
                    borderRadius: 999,
                    background: v.approve ? "rgba(111,162,135,0.15)" : "rgba(193,84,76,0.15)",
                    color: v.approve ? COLORS.sage : COLORS.rust,
                  }}
                >
                  {nameFor(v.address)} {v.approve ? "✓" : "✕"} <SigBadge valid={sigValid["vote:" + v.address]} inline />
                </span>
              ))}
            </div>
          )}

          {isParticipant && !isSubmitter && !alreadyVoted && (
            <div style={{ display: "flex", gap: 10 }}>
              <button
                onClick={() => onVote(true)}
                style={{ ...voteBtnStyle, borderColor: COLORS.sage, color: COLORS.sage }}
              >
                <Check size={16} /> Одобрить
              </button>
              <button
                onClick={() => onVote(false)}
                style={{ ...voteBtnStyle, borderColor: COLORS.rust, color: COLORS.rust }}
              >
                <X size={16} /> Отклонить
              </button>
            </div>
          )}
          {isSubmitter && (
            <div style={{ color: COLORS.textDim, fontSize: 12 }}>Ты отправил(а) это решение — голосуют остальные.</div>
          )}
          {alreadyVoted && (
            <div style={{ color: COLORS.textDim, fontSize: 12 }}>
              Твой голос учтён: {alreadyVoted.approve ? "одобрено" : "отклонено"}.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SigBadge({ valid, inline }) {
  if (valid === undefined) return null;
  const color = valid ? COLORS.sage : COLORS.rust;
  return (
    <span
      title={valid ? "Подпись подтверждена" : "Подпись недействительна"}
      style={{ display: "inline-flex", alignItems: "center", color, marginLeft: inline ? 0 : "auto" }}
    >
      {valid ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
    </span>
  );
}

const iconTextBtnStyle = {
  background: "transparent",
  border: `1px solid ${COLORS.border}`,
  borderRadius: 8,
  padding: "7px 12px",
  color: COLORS.textDim,
  fontSize: 12.5,
  fontFamily: "'Inter',sans-serif",
  fontWeight: 500,
  display: "flex",
  alignItems: "center",
  gap: 5,
};

const voteBtnStyle = {
  flex: 1,
  background: "transparent",
  border: "1.5px solid",
  borderRadius: 10,
  padding: "11px 0",
  fontSize: 14,
  fontWeight: 600,
  fontFamily: "'Inter',sans-serif",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 6,
};

// ---------- Chain tab ----------
function ChainTab({ chain, tasks, identities, onVerify, verifyResult }) {
  const nameFor = (addr) => identities.find((i) => i.address === addr)?.name || shortAddr(addr);
  const titleFor = (taskId) => tasks.find((t) => t.id === taskId)?.title || "задача";

  return (
    <div>
      <SectionTitle>Реестр блоков</SectionTitle>
      <div style={{ ...cardStyle, marginBottom: 16, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ fontSize: 12.5, color: COLORS.textDim }}>
          Каждое одобренное решение навсегда записывается блоком, связанным хэшем с предыдущим.
        </div>
      </div>
      <button
        onClick={onVerify}
        style={{
          width: "100%",
          background: "transparent",
          border: `1px solid ${COLORS.border}`,
          borderRadius: 10,
          padding: "11px 0",
          color: COLORS.text,
          fontFamily: "'Inter',sans-serif",
          fontWeight: 600,
          fontSize: 14,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          marginBottom: 14,
        }}
      >
        <ShieldCheck size={16} color={COLORS.gold} /> Проверить целостность цепи
      </button>
      {verifyResult && (
        <div
          style={{
            ...cardStyle,
            marginBottom: 14,
            borderColor: verifyResult.valid ? COLORS.sage : COLORS.rust,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          {verifyResult.valid ? <ShieldCheck size={16} color={COLORS.sage} /> : <ShieldAlert size={16} color={COLORS.rust} />}
          <span style={{ fontSize: 13, color: verifyResult.valid ? COLORS.sage : COLORS.rust }}>
            {verifyResult.valid ? "Цепь целостна — подделок не найдено" : `Нарушение в блоке #${verifyResult.at}: ${verifyResult.reason}`}
          </span>
        </div>
      )}

      {[...chain].reverse().map((b, i) => (
        <div key={b.hash} style={{ display: "flex", marginBottom: 4 }}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginRight: 10, width: 14 }}>
            <div style={{ width: 8, height: 8, borderRadius: 999, background: b.events.length ? COLORS.gold : COLORS.border, marginTop: 6 }} />
            {i !== chain.length - 1 && <div style={{ flex: 1, width: 1.5, background: COLORS.border, marginTop: 2 }} />}
          </div>
          <div style={{ ...cardStyle, flex: 1, marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "'Roboto Mono',monospace", fontSize: 11, color: COLORS.textDim }}>
              <span>блок #{b.index}</span>
              <span>{fmtTime(b.timestamp)}</span>
            </div>
            {b.events.length === 0 ? (
              <div style={{ fontSize: 12.5, color: COLORS.textDim, marginTop: 6 }}>генезис-блок · без начислений</div>
            ) : (
              b.events.map((e, idx) => (
                <div key={idx} style={{ fontSize: 13, color: COLORS.text, marginTop: 6 }}>
                  «{titleFor(e.taskId)}» одобрена → <span style={{ color: COLORS.gold, fontFamily: "'Roboto Mono',monospace" }}>+{e.amount}</span> монет для{" "}
                  {nameFor(e.to)}
                </div>
              ))
            )}
            <div style={{ fontFamily: "'Roboto Mono',monospace", fontSize: 10.5, color: COLORS.textDim, marginTop: 8, wordBreak: "break-all" }}>
              hash: {b.hash.slice(0, 24)}…
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------- shared bits ----------
function SectionTitle({ children }) {
  return (
    <div
      style={{
        fontSize: 11,
        fontFamily: "'Roboto Mono',monospace",
        color: COLORS.textDim,
        letterSpacing: 1,
        textTransform: "uppercase",
        marginBottom: 10,
      }}
    >
      {children}
    </div>
  );
}

function EmptyState({ icon: Icon, text }) {
  return (
    <div
      style={{
        border: `1px dashed ${COLORS.border}`,
        borderRadius: 12,
        padding: "24px 16px",
        textAlign: "center",
        marginBottom: 12,
      }}
    >
      <Icon size={22} color={COLORS.textDim} style={{ marginBottom: 8 }} />
      <div style={{ color: COLORS.textDim, fontSize: 13, lineHeight: 1.5 }}>{text}</div>
    </div>
  );
}

function BackRow({ onBack, label }) {
  return (
    <button
      onClick={onBack}
      style={{
        background: "transparent",
        border: "none",
        display: "flex",
        alignItems: "center",
        gap: 4,
        color: COLORS.textDim,
        fontSize: 13,
        fontFamily: "'Roboto Mono',monospace",
        padding: 0,
      }}
    >
      <ChevronLeft size={15} /> {label}
    </button>
  );
}

const cardStyle = {
  background: COLORS.surface,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 14,
  padding: "13px 14px",
};
