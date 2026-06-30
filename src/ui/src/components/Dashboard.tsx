import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useTheme } from "@/contexts/ThemeContext";
import { useEngine } from "@/contexts/EngineContext";
import { invoke } from "@tauri-apps/api/core";
import LanguageSwitcher from "./LanguageSwitcher";
import StatusPanel from "./StatusPanel";
import StrategyPanel from "./StrategyPanel";
import ConntrackPanel from "./ConntrackPanel";
import GeoPanel from "./GeoPanel";
import SettingsPanel from "./SettingsPanel";
import ProbePanel from "./ProbePanel";

type Tab = "status" | "strategies" | "connections" | "geo" | "settings" | "probe";

const tabs: Tab[] = ["status", "strategies", "connections", "geo", "settings", "probe"];

export default function Dashboard() {
  const { t } = useTranslation();
  const { theme, setTheme } = useTheme();
  const { isOnline } = useEngine();
  const [activeTab, setActiveTab] = useState<Tab>("status");

  return (
    <div className="flex flex-col h-screen" style={{ background: "var(--bg-base)" }}>
      {/* Header */}
      <header
        className="flex items-center justify-between px-4 py-2 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-2">
          <span className="text-lg font-bold" style={{ color: "var(--accent)" }}>
            {t("app.title")}
          </span>
          <span
            className="text-xs px-2 py-0.5 rounded-full"
            style={{
              background: isOnline ? "var(--accent)" : "var(--destructive)",
              color: "#fff",
            }}
          >
            {isOnline ? t("status.running") : t("status.stopped")}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <LanguageSwitcher />
          <ThemeSwitcher theme={theme} setTheme={setTheme} />
        </div>
      </header>

      {/* Tab Navigation */}
      <nav
        className="flex gap-1 px-4 py-1 border-b overflow-x-auto"
        style={{ borderColor: "var(--border)" }}
      >
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap"
            style={{
              background: activeTab === tab ? "var(--accent)" : "transparent",
              color: activeTab === tab ? "#fff" : "var(--text-secondary)",
            }}
          >
            {t(`nav.${tab}`)}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-auto p-4">
        {activeTab === "status" && (
          <>
            <ProbeWidget />
            <StatusPanel />
          </>
        )}
        {activeTab === "strategies" && <StrategyPanel />}
        {activeTab === "connections" && <ConntrackPanel />}
        {activeTab === "geo" && <GeoPanel />}
        {activeTab === "settings" && <SettingsPanel />}
        {activeTab === "probe" && <ProbePanel />}
      </main>

      {/* Footer */}
      <footer
        className="flex items-center justify-between px-4 py-1.5 text-xs border-t"
        style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
      >
        <span>{t("app.title")} {t("app.version")}</span>
        <span>127.0.0.1:11337</span>
      </footer>
    </div>
  );
}

function ThemeSwitcher({
  theme,
  setTheme,
}: {
  theme: string;
  setTheme: (t: "dark" | "light" | "system") => void;
}) {
  const { t } = useTranslation();
  const options: Array<"light" | "dark" | "system"> = ["light", "dark", "system"];

  return (
    <div className="flex rounded-md overflow-hidden" style={{ border: "1px solid var(--border)" }}>
      {options.map((opt) => (
        <button
          key={opt}
          onClick={() => setTheme(opt)}
          className="px-2 py-1 text-xs transition-colors"
          style={{
            background: theme === opt ? "var(--accent)" : "var(--bg-muted)",
            color: theme === opt ? "#fff" : "var(--text-secondary)",
          }}
        >
          {t(`theme.${opt}`)}
        </button>
      ))}
    </div>
  );
}

interface ProbeResponse {
  domain: string;
  verdict: string;
  confidence: number;
  recommendations: Array<{ strategy_name: string; confidence: number; rationale: string }>;
  timestamp: string;
}

function ProbeWidget() {
  const [lastProbe, setLastProbe] = useState<ProbeResponse | null>(null);

  useEffect(() => {
    const loadHistory = async () => {
      try {
        const history = await invoke<ProbeResponse[]>("get_probe_history");
        if (history && history.length > 0) {
          setLastProbe(history[0]);
        }
      } catch {
        // Service might not be running
      }
    };

    loadHistory();
    const interval = setInterval(loadHistory, 30000);
    return () => clearInterval(interval);
  }, []);

  if (!lastProbe) return null;

  const verdictColor =
    lastProbe.verdict === "blocked"
      ? "var(--destructive)"
      : lastProbe.verdict === "clear"
      ? "var(--accent)"
      : "var(--warning)";

  return (
    <div
      className="probe-widget"
      style={{ marginBottom: "0.75rem" }}
    >
      <h4>DPI Status</h4>
      <div
        className={`status-dot ${lastProbe.verdict}`}
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: verdictColor,
        }}
      />
      <span style={{ color: "var(--text)" }}>{lastProbe.domain}</span>
      <span className="verdict-label" style={{ color: verdictColor }}>
        {lastProbe.verdict}
      </span>
      {lastProbe.recommendations && lastProbe.recommendations.length > 0 && (
        <span className="strategy-label">
          → {lastProbe.recommendations[0].strategy_name}
        </span>
      )}
    </div>
  );
}
