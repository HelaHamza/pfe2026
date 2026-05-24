// ─────────────────────────────────────────────────────────────────────────────
// src/components/dashboard/SigmaSeverityBars.jsx
// Barres horizontales par sévérité — remplace l'ancien affichage en cartes
// ─────────────────────────────────────────────────────────────────────────────

import { severity, neutral } from "../../theme/colors";

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function SigmaSeverityBars({ byLevel }) {
  // byLevel peut être { critical: 24, high: 32, ... } ou { CRITICAL: 24, ... }
  const counts = ORDER.map((k) => ({
    key:   k,
    count: (byLevel?.[k] ?? byLevel?.[k.toLowerCase()] ?? 0),
  }));
  const total = counts.reduce((s, c) => s + c.count, 0);
  const max   = Math.max(...counts.map(c => c.count), 1);

  return (
    <div style={{
      background: neutral.bg,
      border: `1px solid ${neutral.border}`,
      borderRadius: 8,
      padding: "16px 18px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text }}>
          Sigma — répartition par sévérité
        </h3>
        <span style={{ fontSize: 11, color: neutral.textFaint }}>
          {total.toLocaleString("fr-FR")} alerte{total > 1 ? "s" : ""}
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {counts.map(({ key, count }) => {
          const c = severity[key];
          const pct = (count / max) * 100;
          return (
            <div key={key} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{
                fontSize: 11, fontWeight: 600,
                color: c.text, width: 64,
                textTransform: "uppercase", letterSpacing: "0.04em",
              }}>
                {key}
              </span>
              <div style={{ flex: 1, height: 8, background: c.bg, position: "relative" }}>
                <div style={{
                  width: `${pct}%`, height: "100%",
                  background: c.bgStrong,
                  transition: "width 0.4s ease",
                }} />
              </div>
              <span style={{
                fontSize: 12, fontWeight: 600,
                color: count === 0 ? neutral.textFaint : neutral.text,
                width: 32, textAlign: "right",
                fontVariantNumeric: "tabular-nums",
              }}>
                {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}