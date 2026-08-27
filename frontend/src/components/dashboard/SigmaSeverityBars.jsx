const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV = {
  CRITICAL: { solid: "var(--sev-critical)", track: "var(--sev-critical-bg)" },
  HIGH:     { solid: "var(--sev-high)",     track: "var(--sev-high-bg)" },
  MEDIUM:   { solid: "var(--sev-medium)",   track: "var(--sev-medium-bg)" },
  LOW:      { solid: "var(--sev-low)",      track: "var(--sev-low-bg)" },
};

// Donut SVG empilé — chaque niveau est un arc, dimensionné à sa part du total.
function SeverityDonut({ counts, total }) {
  const size = 128, stroke = 18, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  let cumulative = 0;

  return (
    <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none"
                stroke="var(--surface-sunk)" strokeWidth={stroke} />
        {total > 0 && counts.map(({ key, count }) => {
          if (count === 0) return null;
          const len    = (count / total) * c;
          const offset = -cumulative;
          cumulative += len;
          return (
            <circle
              key={key}
              cx={size / 2} cy={size / 2} r={r} fill="none"
              stroke={SEV[key].solid} strokeWidth={stroke}
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={offset}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
              style={{ transition: "stroke-dasharray .4s var(--ease)" }}
            />
          );
        })}
      </svg>
      <div style={{
        position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)",
                       fontVariantNumeric: "tabular-nums", lineHeight: 1 }}>
          {total.toLocaleString("fr-FR")}
        </span>
        <span style={{ fontSize: 9, color: "var(--text-faint)", textTransform: "uppercase",
                       letterSpacing: ".04em", marginTop: 2 }}>
          alerte{total > 1 ? "s" : ""}
        </span>
      </div>
    </div>
  );
}

export default function SigmaSeverityBars({ byLevel }) {
  const counts = ORDER.map((k) => ({
    key: k, count: byLevel?.[k] ?? byLevel?.[k.toLowerCase()] ?? 0,
  }));
  const total = counts.reduce((s, c) => s + c.count, 0);

  return (
    <section className="card" style={{ display: "flex", flexDirection: "column" }}>
      <div className="card__head">
        <h3 className="card__title">Sigma — répartition par sévérité</h3>
        <span className="card__hint">
          {total.toLocaleString("fr-FR")} alerte{total > 1 ? "s" : ""}
        </span>
      </div>

      {total === 0 ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
                      color: "var(--text-faint)", fontSize: 12 }}>
          Aucune alerte Sigma sur ce run
        </div>
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "var(--sp-5)" }}>
          <SeverityDonut counts={counts} total={total} />

          {/* Légende — les 4 niveaux toujours listés, y compris à 0 */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "var(--sp-3)" }}>
            {counts.map(({ key, count }) => (
              <div key={key} style={{ display: "flex", alignItems: "center", gap: "var(--sp-3)" }}>
                <span style={{
                  width: 10, height: 10, borderRadius: 3, flexShrink: 0,
                  background: count === 0 ? "var(--surface-sunk)" : SEV[key].solid,
                  border: count === 0 ? "1px solid var(--border-strong)" : "none",
                }} />
                <span style={{ flex: 1, fontSize: 12, fontWeight: 600,
                               color: count === 0 ? "var(--text-faint)" : SEV[key].solid,
                               textTransform: "uppercase", letterSpacing: ".04em",
                               fontFamily: "var(--font-mono)" }}>
                  {key}
                </span>
                <span style={{ fontSize: 13, fontWeight: 700, textAlign: "right",
                               color: count === 0 ? "var(--text-faint)" : "var(--text)",
                               fontVariantNumeric: "tabular-nums", fontFamily: "var(--font-mono)" }}>
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
