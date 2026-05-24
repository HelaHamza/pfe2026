// ─────────────────────────────────────────────────────────────────────────────
// src/components/dashboard/Securitytable.jsx
// Refonte : bordure gauche colorée par sévérité (standard SIEM)
//           + fond teinté léger pour les lignes CRITICAL
//           + colonne TYPE supprimée → titre prend plus d'espace
// ─────────────────────────────────────────────────────────────────────────────

import { useState } from "react";
import { severity, detection, neutral } from "../../theme/colors";

const SRC_LABEL = {
  both:       "AE + Σ",
  ae_only:    "AE",
  sigma_only: "Σ Sigma",
};

function SevBadge({ level }) {
  const k = (level || "").toUpperCase();
  const t = severity[k] || { text: neutral.textMuted, bg: neutral.bgMuted, border: neutral.border };
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 4,
      fontSize: 10, fontWeight: 700,
      letterSpacing: "0.06em", textTransform: "uppercase", whiteSpace: "nowrap",
      color: t.text, background: t.bg, border: `1px solid ${t.border}`,
    }}>
      {level || "—"}
    </span>
  );
}

function SrcBadge({ source }) {
  const c     = detection[source] || neutral.textMuted;
  const label = SRC_LABEL[source] || source;
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 4,
      fontSize: 10, fontWeight: 600,
      color: c, background: c + "18", border: `1px solid ${c}30`,
      whiteSpace: "nowrap",
    }}>
      {label}
    </span>
  );
}

const COL = "100px 1fr 160px 100px 90px 70px";
const PAGE_SIZE = 10;

function FilterPill({ value, label, color, current, setF }) {
  const active = current === value;
  return (
    <button
      onClick={() => setF(active && value !== "" ? "" : value)}
      style={{
        padding: "4px 12px", borderRadius: 16, fontSize: 11,
        border: "none", cursor: "pointer", fontWeight: 600,
        background: active ? color : neutral.bgMuted,
        color:      active ? "#fff" : neutral.textMuted,
        transition: "background 0.15s",
      }}
    >
      {label}
    </button>
  );
}

export default function SecurityTable({ results, onSelect, selected }) {
  const [sevF,   setSevF]   = useState("");
  const [srcF,   setSrcF]   = useState("");
  const [search, setSearch] = useState("");
  const [page,   setPage]   = useState(1);

  // Normalisation (AE = kb_severity, Sigma = level)
  const normalize = (r) => ({
    ...r,
    _severity: (r.kb_severity || r.severity || r.level || "").toUpperCase(),
    _source:   (r.detection_source || "").toLowerCase(),
    _text:     (r.title || r.log_source || "").toLowerCase(),
  });

  const filtered = (results || [])
    .map(normalize)
    .filter((r) =>
      (!sevF   || r._severity === sevF) &&
      (!srcF   || r._source   === srcF) &&
      (!search || r._text.includes(search.toLowerCase()))
    );

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const paginated  = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const handleSevF   = (v) => { setSevF(v);   setPage(1); };
  const handleSrcF   = (v) => { setSrcF(v);   setPage(1); };
  const handleSearch = (v) => { setSearch(v); setPage(1); };

  return (
    <div style={{ paddingTop: 20 }}>
      <div style={{
        display: "flex", alignItems: "baseline", justifyContent: "space-between",
        marginBottom: 12,
      }}>
        <h2 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: neutral.text }}>
          Alertes de sécurité
        </h2>
        <span style={{ fontSize: 11, color: neutral.textFaint }}>
          {filtered.length} résultat{filtered.length > 1 ? "s" : ""}
        </span>
      </div>

      {/* ── Filtres ── */}
      <div style={{
        display: "flex", gap: 6, marginBottom: 12,
        flexWrap: "wrap", alignItems: "center",
      }}>
        <div style={{ position: "relative", marginRight: 4 }}>
          <span style={{
            position: "absolute", left: 9, top: "50%",
            transform: "translateY(-50%)", fontSize: 11, color: neutral.textFaint,
            pointerEvents: "none",
          }}>⌕</span>
          <input
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Rechercher..."
            style={{
              border: `1px solid ${neutral.border}`, borderRadius: 16,
              padding: "5px 14px 5px 26px", fontSize: 11,
              color: neutral.text, outline: "none",
              background: neutral.bgAlt, width: 180,
            }}
          />
        </div>

        {[
          ["",         "#185FA5",                 "Toutes"],
          ["CRITICAL", severity.CRITICAL.bgStrong, "Critical"],
          ["HIGH",     severity.HIGH.bgStrong,     "High"],
          ["MEDIUM",   severity.MEDIUM.bgStrong,   "Medium"],
          ["LOW",      severity.LOW.bgStrong,      "Low"],
        ].map(([v, c, l]) => (
          <FilterPill key={`sev-${v}`} value={v} label={l} color={c} current={sevF} setF={handleSevF} />
        ))}

        <div style={{
          width: 1, height: 18, background: neutral.border, margin: "0 4px",
        }} />

        {[
          ["",           "#185FA5",          "Toutes sources"],
          ["ae_only",    detection.ae_only,    "AE"],
          ["sigma_only", detection.sigma_only, "Sigma"],
          ["both",       detection.both,       "AE + Σ"],
        ].map(([v, c, l]) => (
          <FilterPill key={`src-${v}`} value={v} label={l} color={c} current={srcF} setF={handleSrcF} />
        ))}
      </div>

      {/* ── Tableau ── */}
      <div style={{
        border: `1px solid ${neutral.border}`, borderRadius: 8, overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          display: "grid", gridTemplateColumns: COL,
          padding: "8px 14px", background: neutral.bgAlt,
          borderBottom: `1px solid ${neutral.border}`,
          fontSize: 10, fontWeight: 600,
          textTransform: "uppercase", letterSpacing: "0.06em",
          color: neutral.textMuted,
        }}>
          {["Time", "Titre / Règle", "Tactique", "Sévérité", "Source", "Score"].map((h) => (
            <span key={h}>{h}</span>
          ))}
        </div>

        {/* Lignes */}
        {paginated.length === 0 ? (
          <div style={{
            padding: "32px 14px", textAlign: "center",
            color: neutral.textFaint, fontSize: 13,
          }}>
            Aucun événement
          </div>
        ) : (
          paginated.map((r, i) => {
            const sev   = severity[r._severity];
            const isOpen = selected?.id === r.id;
            const isCritical = r._severity === "CRITICAL";

            const score = r.ae_anomaly_score != null
              ? (r.ae_anomaly_score * 100).toFixed(1) + "%"
              : (r.score != null ? r.score : "—");

            // Bordure gauche colorée + fond teinté pour critiques
            const leftBorder = sev ? sev.bgStrong : neutral.border;
            const rowBg = isOpen
              ? "#eff6ff"
              : isCritical
                ? severity.CRITICAL.bg
                : (i % 2 === 0 ? neutral.bg : neutral.bgAlt);

            return (
              <div
                key={r.id || i}
                onClick={() => onSelect(isOpen ? null : r)}
                style={{
                  display: "grid", gridTemplateColumns: COL,
                  alignItems: "center", padding: "9px 14px 9px 11px",
                  borderBottom: `1px solid ${neutral.borderSoft}`,
                  borderLeft: `3px solid ${leftBorder}`,
                  cursor: "pointer", background: rowBg,
                  transition: "background 0.1s",
                }}
                onMouseEnter={(e) => { if (!isOpen) e.currentTarget.style.background = "#eff6ff"; }}
                onMouseLeave={(e) => { if (!isOpen) e.currentTarget.style.background = rowBg; }}
              >
                <span style={{
                  fontSize: 11, color: neutral.textMuted,
                  fontFamily: "ui-monospace, monospace",
                }}>
                  {r["@timestamp"]?.replace("T", " ").slice(11, 19) ?? "—"}
                </span>
                <span style={{
                  fontSize: 12, fontWeight: isCritical ? 600 : 500,
                  color: neutral.text,
                  overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "nowrap", paddingRight: 12,
                }}>
                  {r.title || r.log_source || "—"}
                </span>
                <span style={{
                  fontSize: 11, color: neutral.textMuted,
                  overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "nowrap", paddingRight: 8,
                }}>
                  {r.tactic || "—"}
                </span>
                <SevBadge level={r._severity} />
                <SrcBadge source={r.detection_source} />
                <span style={{
                  fontSize: 11, fontFamily: "ui-monospace, monospace",
                  color: isCritical ? severity.CRITICAL.text : neutral.textMuted,
                  fontWeight: isCritical ? 600 : 400,
                  textAlign: "right",
                }}>
                  {score}
                </span>
              </div>
            );
          })
        )}

        {/* ── Pagination ── */}
        <div style={{
          padding: "10px 14px", background: neutral.bgAlt,
          borderTop: `1px solid ${neutral.borderSoft}`,
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          <span style={{ fontSize: 10, color: neutral.textFaint }}>
            <code style={{ color: detection.sigma_only }}>sigma-alerts</code>
            {" · "}
            <code style={{ color: detection.ae_only }}>ml-autoencoder-scores</code>
          </span>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 11, color: neutral.textMuted, marginRight: 4 }}>
              Page {safePage} / {totalPages}
              <span style={{ color: neutral.textFaint, marginLeft: 4 }}>
                ({(safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} sur {filtered.length})
              </span>
            </span>
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={safePage === 1}
              style={{
                padding: "3px 10px", borderRadius: 6, border: `1px solid ${neutral.border}`,
                background: safePage === 1 ? neutral.bgAlt : neutral.bg,
                color: safePage === 1 ? neutral.textGhost : neutral.text,
                cursor: safePage === 1 ? "default" : "pointer",
                fontSize: 12, fontWeight: 600,
              }}
            >
              ←
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              let p;
              if (totalPages <= 5)               p = i + 1;
              else if (safePage <= 3)            p = i + 1;
              else if (safePage >= totalPages-2) p = totalPages - 4 + i;
              else                               p = safePage - 2 + i;
              const active = p === safePage;
              return (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  style={{
                    padding: "3px 8px", borderRadius: 6,
                    border: `1px solid ${active ? "#185FA5" : neutral.border}`,
                    background: active ? "#185FA5" : neutral.bg,
                    color:      active ? "#fff"    : neutral.text,
                    cursor: "pointer", fontSize: 11, fontWeight: 600,
                    minWidth: 28,
                  }}
                >
                  {p}
                </button>
              );
            })}
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={safePage === totalPages}
              style={{
                padding: "3px 10px", borderRadius: 6, border: `1px solid ${neutral.border}`,
                background: safePage === totalPages ? neutral.bgAlt : neutral.bg,
                color: safePage === totalPages ? neutral.textGhost : neutral.text,
                cursor: safePage === totalPages ? "default" : "pointer",
                fontSize: 12, fontWeight: 600,
              }}
            >
              →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}