import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./ProbePanel.css";

interface PhaseResult {
  phase: string;
  status: string;
  detail: string;
  latency_us?: number;
}

interface Recommendation {
  strategy_name: string;
  confidence: number;
  rationale: string;
}

interface ProbeResult {
  domain: string;
  verdict: string;
  confidence: number;
  dns: PhaseResult;
  tcp: PhaseResult;
  tls?: PhaseResult;
  http?: PhaseResult;
  tcp16?: PhaseResult;
  recommendations: Recommendation[];
  should_tunnel?: boolean;
  timestamp: string;
}

interface PresetList {
  id: string;
  name: string;
  category: string;
  domain_count: number;
}

interface CustomList {
  id: string;
  name: string;
  domains: string[];
  created_at: string;
  updated_at: string;
}

export default function ProbePanel() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProbeResult | null>(null);
  const [presets, setPresets] = useState<PresetList[]>([]);
  const [selectedPresets, setSelectedPresets] = useState<string[]>([]);
  const [batchResults, setBatchResults] = useState<ProbeResult[]>([]);
  const [batchLoading, setBatchLoading] = useState(false);
  const [history, setHistory] = useState<ProbeResult[]>([]);
  const [customLists, setCustomLists] = useState<CustomList[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingList, setEditingList] = useState<CustomList | null>(null);

  // Load presets and custom lists on mount
  useEffect(() => {
    invoke<PresetList[]>("get_probe_presets")
      .then(setPresets)
      .catch(console.error);
    invoke<CustomList[]>("get_custom_lists")
      .then(setCustomLists)
      .catch(console.error);
  }, []);

  const handleProbe = async (full: boolean) => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const res = await invoke<ProbeResult>("run_probe", {
        domain: domain.trim(),
        full,
      });
      setResult(res);
      setHistory((prev) => [res, ...prev].slice(0, 50));
    } catch (err) {
      console.error("Probe failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const togglePreset = (id: string) => {
    setSelectedPresets((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]
    );
  };

  const handleBatchProbe = async () => {
    if (selectedPresets.length === 0) return;
    setBatchLoading(true);
    try {
      const results = await invoke<ProbeResponse[]>("run_batch_probe", {
        presetIds: selectedPresets,
        full: true,
      });
      setBatchResults(results);
    } catch (err) {
      console.error("Batch probe failed:", err);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleSaveCustomList = async (list: CustomList) => {
    try {
      await invoke("save_custom_list", { list });
      const updated = await invoke<CustomList[]>("get_custom_lists");
      setCustomLists(updated);
      setShowCreateModal(false);
      setEditingList(null);
    } catch (err) {
      console.error("Save failed:", err);
    }
  };

  const handleDeleteCustomList = async (id: string) => {
    try {
      await invoke("delete_custom_list", { id });
      const updated = await invoke<CustomList[]>("get_custom_lists");
      setCustomLists(updated);
    } catch (err) {
      console.error("Delete failed:", err);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "ok":
        return "var(--accent)";
      case "blocked":
        return "var(--destructive)";
      default:
        return "var(--muted)";
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case "blocked":
        return "var(--destructive)";
      case "clear":
        return "var(--accent)";
      default:
        return "var(--warning)";
    }
  };

  return (
    <div className="probe-panel space-y-4">
      {/* Input with two buttons */}
      <div className="probe-input">
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleProbe(false);
          }}
          placeholder="example.com"
          disabled={loading}
        />
        <button
          className="quick"
          onClick={() => handleProbe(false)}
          disabled={loading || !domain.trim()}
        >
          {loading ? "..." : "Быстрая"}
        </button>
        <button
          className="full"
          onClick={() => handleProbe(true)}
          disabled={loading || !domain.trim()}
        >
          {loading ? "..." : "Полная"}
        </button>
      </div>

      {/* Preset selector */}
      {presets.length > 0 && (
        <div className="preset-selector">
          <div className="preset-chips">
            {presets.map((p) => (
              <button
                key={p.id}
                onClick={() => togglePreset(p.id)}
                className={`preset-chip ${selectedPresets.includes(p.id) ? "active" : ""}`}
              >
                {p.name} ({p.domain_count})
              </button>
            ))}
          </div>
          {selectedPresets.length > 0 && (
            <button
              className="batch-probe-btn"
              onClick={handleBatchProbe}
              disabled={batchLoading}
              style={{
                marginTop: "0.5rem",
                padding: "0.375rem 0.75rem",
                background: "var(--accent)",
                color: "white",
                border: "none",
                borderRadius: "0.375rem",
                cursor: batchLoading ? "not-allowed" : "pointer",
                opacity: batchLoading ? 0.6 : 1,
              }}
            >
              {batchLoading ? "Проверка..." : `Проверить выбранные (${selectedPresets.length})`}
            </button>
          )}
        </div>
      )}

      {/* Pipeline visualization */}
      {result && (
        <div className="probe-pipeline">
          <PhaseCard phase={result.dns} />
          <span className="pipeline-arrow">→</span>
          <PhaseCard phase={result.tcp} />
          <span className="pipeline-arrow">→</span>
          {result.tls && <PhaseCard phase={result.tls} />}
          {result.tls && <span className="pipeline-arrow">→</span>}
          {result.http && <PhaseCard phase={result.http} />}
          {result.http && result.tcp16 && <span className="pipeline-arrow">→</span>}
          {result.tcp16 && <PhaseCard phase={result.tcp16} />}
        </div>
      )}

      {/* Verdict */}
      {result && (
        <div className={`probe-verdict ${result.verdict}`}>
          <h3 style={{ color: getVerdictColor(result.verdict) }}>
            {result.verdict.toUpperCase()}
          </h3>
          <div style={{ color: "var(--text-secondary)" }}>
            Confidence: {(result.confidence * 100).toFixed(0)}%
          </div>
          {result.should_tunnel && (
            <div style={{ color: "var(--destructive)", marginTop: "0.25rem" }}>
              Should tunnel (accumulated verdict)
            </div>
          )}
        </div>
      )}

      {/* Recommendations */}
      {result && result.recommendations.length > 0 && (
        <div className="probe-recommendations">
          <h4 style={{ color: "var(--text)" }}>Рекомендуемые стратегии:</h4>
          {result.recommendations.map((rec, i) => (
            <div key={i} className="recommendation-card">
              <div className="flex justify-between">
                <span className="strategy-name">{rec.strategy_name}</span>
                <span className="confidence">
                  {(rec.confidence * 100).toFixed(0)}%
                </span>
              </div>
              <div className="rationale">{rec.rationale}</div>
            </div>
          ))}
        </div>
      )}

      {/* Custom Lists */}
      <div style={{ marginBottom: "1rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
          <h4 style={{ color: "var(--text)", margin: 0 }}>Мои списки:</h4>
          <button
            onClick={() => setShowCreateModal(true)}
            style={{
              padding: "0.25rem 0.5rem",
              background: "var(--accent)",
              color: "white",
              border: "none",
              borderRadius: "0.375rem",
              cursor: "pointer",
              fontSize: "0.75rem",
            }}
          >
            + Создать
          </button>
        </div>
        {customLists.map((list) => (
          <div
            key={list.id}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "0.375rem 0.5rem",
              border: "1px solid var(--border)",
              borderRadius: "0.375rem",
              marginBottom: "0.25rem",
            }}
          >
            <span style={{ color: "var(--text)" }}>
              {list.name} ({list.domains.length} доменов)
            </span>
            <div style={{ display: "flex", gap: "0.25rem" }}>
              <button
                onClick={() => setEditingList(list)}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-secondary)" }}
              >
                Edit
              </button>
              <button
                onClick={() => handleDeleteCustomList(list.id)}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--destructive)" }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Create/Edit Modal */}
      {showCreateModal && (
        <ListEditorModal
          list={editingList}
          onSave={handleSaveCustomList}
          onClose={() => {
            setShowCreateModal(false);
            setEditingList(null);
          }}
        />
      )}

      {/* Batch results */}
      {batchResults.length > 0 && (
        <div className="probe-history">
          <h4 style={{ color: "var(--text)" }}>
            Результаты:{" "}
            <span style={{ color: "var(--accent)" }}>
              {batchResults.filter((r) => r.verdict === "clear").length} OK
            </span>{" "}
            /{" "}
            <span style={{ color: "var(--destructive)" }}>
              {batchResults.filter((r) => r.verdict === "blocked").length} Blocked
            </span>{" "}
            /{" "}
            <span style={{ color: "var(--warning)" }}>
              {batchResults.filter((r) => r.verdict === "ambiguous").length} Ambiguous
            </span>
          </h4>
          <table>
            <thead>
              <tr>
                <th>Домен</th>
                <th>DNS</th>
                <th>TCP</th>
                <th>TLS</th>
                <th>HTTP</th>
                <th>Вердикт</th>
              </tr>
            </thead>
            <tbody>
              {batchResults.map((r, i) => (
                <tr key={i} className={r.verdict}>
                  <td>{r.domain}</td>
                  <td>{r.dns?.detail}</td>
                  <td>{r.tcp?.detail}</td>
                  <td>{r.tls?.detail || "-"}</td>
                  <td>{r.http?.detail || "-"}</td>
                  <td style={{ fontWeight: 600 }}>{r.verdict}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="probe-history">
          <h4 style={{ color: "var(--text)" }}>История проверок:</h4>
          <table>
            <thead>
              <tr>
                <th>Домен</th>
                <th>Вердикт</th>
                <th>TLS</th>
                <th>Время</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i} className={h.verdict}>
                  <td>{h.domain}</td>
                  <td>{h.verdict}</td>
                  <td>{h.tls?.detail || h.tcp?.detail}</td>
                  <td>{new Date(h.timestamp).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function PhaseCard({ phase }: { phase: PhaseResult }) {
  const color =
    phase.status === "ok"
      ? "var(--accent)"
      : phase.status === "blocked"
      ? "var(--destructive)"
      : "var(--muted)";

  return (
    <div className="phase-card" style={{ borderColor: color }}>
      <div className="phase-name">{phase.phase.toUpperCase()}</div>
      <div className="phase-status" style={{ color }}>
        {phase.status}
      </div>
      <div className="phase-detail">{phase.detail}</div>
      {phase.latency_us != null && (
        <div className="phase-latency">
          {(phase.latency_us / 1000).toFixed(1)}ms
        </div>
      )}
    </div>
  );
}

function ListEditorModal({
  list,
  onSave,
  onClose,
}: {
  list: CustomList | null;
  onSave: (list: CustomList) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(list?.name || "");
  const [domainText, setDomainText] = useState(list?.domains.join("\n") || "");

  const handleSave = async () => {
    const domains = await invoke<string[]>("import_domains_from_text", {
      text: domainText,
    });
    onSave({
      id: list?.id || crypto.randomUUID(),
      name,
      domains,
      created_at: list?.created_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.7)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
    >
      <div
        style={{
          background: "#1f2937",
          border: "1px solid #374151",
          borderRadius: "0.75rem",
          padding: "1.5rem",
          width: "500px",
          maxHeight: "80vh",
          overflowY: "auto",
        }}
      >
        <h3 style={{ color: "#f9fafb", marginBottom: "1rem" }}>
          {list ? "Редактировать список" : "Новый список"}
        </h3>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Название списка"
          style={{
            width: "100%",
            padding: "0.5rem",
            border: "1px solid #374151",
            borderRadius: "0.375rem",
            background: "#111827",
            color: "#f9fafb",
            marginBottom: "0.75rem",
          }}
        />
        <textarea
          value={domainText}
          onChange={(e) => setDomainText(e.target.value)}
          placeholder={"example.com\nyoutube.com\ntelegram.org\n\n# комментарии игнорируются"}
          rows={15}
          style={{
            width: "100%",
            padding: "0.5rem",
            border: "1px solid #374151",
            borderRadius: "0.375rem",
            background: "#111827",
            color: "#f9fafb",
            marginBottom: "0.75rem",
            fontFamily: "monospace",
            fontSize: "0.875rem",
          }}
        />
        <div style={{ fontSize: "0.75rem", color: "#9ca3af", marginBottom: "0.75rem" }}>
          Доменов: {domainText.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length}
        </div>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end" }}>
          <button
            onClick={onClose}
            style={{
              padding: "0.5rem 1rem",
              border: "1px solid #374151",
              borderRadius: "0.375rem",
              background: "transparent",
              color: "#d1d5db",
              cursor: "pointer",
            }}
          >
            Отмена
          </button>
          <button
            onClick={handleSave}
            disabled={!name.trim()}
            style={{
              padding: "0.5rem 1rem",
              border: "none",
              borderRadius: "0.375rem",
              background: name.trim() ? "#3b82f6" : "#4b5563",
              color: "white",
              cursor: name.trim() ? "pointer" : "not-allowed",
            }}
          >
            Сохранить
          </button>
        </div>
      </div>
    </div>
  );
}
