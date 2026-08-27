import { useState } from "react";

// Contrat actuel : une row = une branche. `type` ∈ { "cnn", "sigma" }.
const SRC_LABEL = {
  cnn:   "CNN-AE",
  sigma: "Σ Sigma",
};

const SEV_VAR = {
  CRITICAL: { solid: "var(--sev-critical)", bg: "var(--sev-critical-bg)" },
  HIGH:     { solid: "var(--sev-high)",     bg: "var(--sev-high-bg)" },
  MEDIUM:   { solid: "var(--sev-medium)",   bg: "var(--sev-medium-bg)" },
  LOW:      { solid: "var(--sev-low)",      bg: "var(--sev-low-bg)" },
};

const SRC_VAR = {
  cnn:   { solid: "var(--det-cnn)",   bg: "var(--det-cnn-bg)" },
  sigma: { solid: "var(--det-sigma)", bg: "var(--det-sigma-bg)" },
};

function SevBadge({ level }) {
  const k = (level || "").toUpperCase();
  const t = SEV_VAR[k] || { solid: "var(--text-faint)", bg: "var(--surface-sunk)" };
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 4,
      fontSize: 10, fontWeight: 700,
      letterSpacing: "0.06em", textTransform: "uppercase", whiteSpace: "nowrap",
      color: t.solid, background: t.bg, border: `1px solid ${t.solid}`,
    }}>
      {level || "—"}
    </span>
  );
}

function SrcBadge({ source }) {
  const t     = SRC_VAR[source] || { solid: "var(--text-faint)", bg: "var(--surface-sunk)" };
  const label = SRC_LABEL[source] || source;
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 4,
      fontSize: 10, fontWeight: 600,
      color: t.solid, background: t.bg, border: `1px solid ${t.solid}`,
      whiteSpace: "nowrap",
    }}>
      {label}
    </span>
  );
}

const COL = "100px 1fr 100px 90px 70px";
const PAGE_SIZE = 10;

function FilterPill({ value, label, color, current, setF }) {
  const active = current === value;
  return (
    <button
      onClick={() => setF(active && value !== "" ? "" : value)}
      style={{
        padding: "4px 12px", borderRadius: 16, fontSize: 11,
        border: "none", cursor: "pointer", fontWeight: 600,
        background: active ? color : "var(--surface-sunk)",
        color:      active ? "var(--bg)" : "var(--text-soft)",
        transition: "background 0.15s",
      }}
    >
      {label}
    </button>
  );
}

export default function SecurityTable({ results, onSelect, selected, emptyHint }) {
  const [sevF,   setSevF]   = useState("");
  const [srcF,   setSrcF]   = useState("");
  const [search, setSearch] = useState("");
  const [page,   setPage]   = useState(1);

  const normalize = (r) => ({
    ...r,
    _severity: (r.severity || "").toUpperCase(),
    _source:   (r.type || "").toLowerCase(),
    _text:     (r.title || r.log_source || "").toLowerCase(),
  });

  const rawEmpty = (results || []).length === 0;

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
    <div className="card">
      <div className="card__head" style={{ marginBottom: 12 }}>
        <h2 className="card__title">
          Alertes de sécurité
        </h2>
        <span className="card__hint">
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
            transform: "translateY(-50%)", fontSize: 11, color: "var(--text-faint)",
            pointerEvents: "none",
          }}>⌕</span>
          <input
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Rechercher..."
            style={{
              border: "1px solid var(--border)", borderRadius: 16,
              padding: "5px 14px 5px 26px", fontSize: 11,
              color: "var(--text)", outline: "none",
              background: "var(--surface-sunk)", width: 180,
            }}
          />
        </div>

        {[
          ["",         "var(--accent)",       "Toutes"],
          ["CRITICAL", "var(--sev-critical)", "Critical"],
          ["HIGH",     "var(--sev-high)",     "High"],
          ["MEDIUM",   "var(--sev-medium)",   "Medium"],
          ["LOW",      "var(--sev-low)",      "Low"],
        ].map(([v, c, l]) => (
          <FilterPill key={`sev-${v}`} value={v} label={l} color={c} current={sevF} setF={handleSevF} />
        ))}

        <div style={{
          width: 1, height: 18, background: "var(--border-strong)", margin: "0 4px",
        }} />

        {[
          ["",      "var(--accent)",    "Toutes sources"],
          ["cnn",   "var(--det-cnn)",   "CNN-AE"],
          ["sigma", "var(--det-sigma)", "Sigma"],
        ].map(([v, c, l]) => (
          <FilterPill key={`src-${v}`} value={v} label={l} color={c} current={srcF} setF={handleSrcF} />
        ))}
      </div>

      {/* ── Tableau ── */}
      <div style={{
        border: "1px solid var(--border-strong)", borderRadius: "var(--r-md)", overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          display: "grid", gridTemplateColumns: COL,
          padding: "8px 14px", background: "var(--surface-2)",
          borderBottom: "1px solid var(--border-strong)",
          fontSize: 10, fontWeight: 600,
          textTransform: "uppercase", letterSpacing: "0.06em",
          color: "var(--text-soft)",
        }}>
          {["Time", "Titre / Règle", "Sévérité", "Source", "Volume"].map((h) => (
            <span key={h}>{h}</span>
          ))}
        </div>

        {/* Lignes */}
        {paginated.length === 0 ? (
          <div style={{
            padding: "32px 14px", textAlign: "center",
            color: "var(--text-faint)", fontSize: 13, lineHeight: 1.6,
          }}>
            {rawEmpty && emptyHint ? emptyHint : "Aucun événement"}
          </div>
        ) : (
          paginated.map((r, i) => {
            const sev   = SEV_VAR[r._severity];
            const isOpen = selected?.id === r.id;
            const isCritical = r._severity === "CRITICAL";

            const volume = r.hits != null ? r.hits : "—";

            const leftBorder = sev ? sev.solid : "var(--border)";
            const rowBg = isOpen
              ? "var(--accent-soft)"
              : isCritical
                ? "var(--sev-critical-bg)"
                : (i % 2 === 0 ? "var(--surface)" : "var(--surface-2)");

            return (
              <div
                key={r.id || i}
                onClick={() => onSelect(isOpen ? null : r)}
                style={{
                  display: "grid", gridTemplateColumns: COL,
                  alignItems: "center", padding: "9px 14px 9px 11px",
                  borderBottom: "1px solid var(--border)",
                  borderLeft: `3px solid ${leftBorder}`,
                  cursor: "pointer", background: rowBg,
                  transition: "background 0.1s",
                }}
                onMouseEnter={(e) => { if (!isOpen) e.currentTarget.style.background = "var(--accent-soft)"; }}
                onMouseLeave={(e) => { if (!isOpen) e.currentTarget.style.background = rowBg; }}
              >
                <span style={{
                  fontSize: 11, color: "var(--text-soft)",
                  fontFamily: "var(--font-mono)",
                }}>
                  {r.event_time?.replace("T", " ").slice(11, 19) ?? "—"}
                  {r.event_time_estimated ? " *" : ""}
                </span>
                <span style={{
                  fontSize: 12, fontWeight: isCritical ? 600 : 500,
                  color: "var(--text)",
                  overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "nowrap", paddingRight: 12,
                }}>
                  {r.title || r.log_source || "—"}
                </span>
                <SevBadge level={r._severity} />
                <SrcBadge source={r.type} />
                <span style={{
                  fontSize: 11, fontFamily: "var(--font-mono)",
                  color: isCritical ? "var(--sev-critical)" : "var(--text-soft)",
                  fontWeight: isCritical ? 600 : 400,
                  textAlign: "right",
                }}>
                  {volume}
                </span>
              </div>
            );
          })
        )}

        {/* ── Pagination ── */}
        <div style={{
          padding: "10px 14px", background: "var(--surface-2)",
          borderTop: "1px solid var(--border)",
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 11, color: "var(--text-soft)", marginRight: 4 }}>
              Page {safePage} / {totalPages}
              <span style={{ color: "var(--text-faint)", marginLeft: 4 }}>
                ({filtered.length === 0 ? 0 : (safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} sur {filtered.length})
              </span>
            </span>
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={safePage === 1}
              style={{
                padding: "3px 10px", borderRadius: 6, border: "1px solid var(--border)",
                background: safePage === 1 ? "var(--surface-2)" : "var(--surface)",
                color: safePage === 1 ? "var(--text-faint)" : "var(--text)",
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
                    border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                    background: active ? "var(--accent)" : "var(--surface)",
                    color:      active ? "var(--bg)"      : "var(--text)",
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
                padding: "3px 10px", borderRadius: 6, border: "1px solid var(--border)",
                background: safePage === totalPages ? "var(--surface-2)" : "var(--surface)",
                color: safePage === totalPages ? "var(--text-faint)" : "var(--text)",
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