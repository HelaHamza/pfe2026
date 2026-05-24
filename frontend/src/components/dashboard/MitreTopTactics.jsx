// ─────────────────────────────────────────────────────────────────────────────
// src/components/dashboard/MitreTopTactics.jsx
// Liste classée des tactiques MITRE (au lieu du donut illisible)
// Garde une mini-bar à droite pour la lecture rapide
// ─────────────────────────────────────────────────────────────────────────────

import { mitre as mitreColors, neutral } from "../../theme/colors";

export default function MitreTopTactics({ data, limit = 8 }) {
  const items = (data || [])
    .map((d) => ({
      label: d.tactic || d.level || "Inconnu",
      count: d.count ?? 0,
    }))
    .filter((d) => d.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

  const max = items.length ? items[0].count : 1;

  return (
    <div style={{
      background: neutral.bg,
      border: `1px solid ${neutral.border}`,
      borderRadius: 8,
      padding: "16px 18px",
      minHeight: 220,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text }}>
          MITRE ATT&CK · top tactiques
        </h3>
        {items.length > 0 && (
          <span style={{ fontSize: 11, color: neutral.textFaint }}>
            top {items.length}
          </span>
        )}
      </div>

      {items.length === 0 ? (
        <div style={{
          fontSize: 12, color: neutral.textFaint,
          textAlign: "center", padding: "30px 0",
        }}>
          Aucune tactique détectée
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {items.map((d, i) => (
            <div key={d.label} style={{
              display: "flex", alignItems: "center", gap: 10,
              fontSize: 12, color: neutral.text,
            }}>
              <span style={{
                width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                background: mitreColors[i % mitreColors.length],
              }} />
              <span style={{
                flex: 1, whiteSpace: "nowrap",
                overflow: "hidden", textOverflow: "ellipsis",
              }} title={d.label}>
                {d.label}
              </span>
              <div style={{
                width: 70, height: 4, background: neutral.bgMuted, flexShrink: 0,
              }}>
                <div style={{
                  width: `${(d.count / max) * 100}%`, height: "100%",
                  background: mitreColors[i % mitreColors.length],
                }} />
              </div>
              <span style={{
                fontWeight: 600, color: neutral.textMuted,
                fontVariantNumeric: "tabular-nums",
                width: 28, textAlign: "right",
              }}>
                {d.count}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}