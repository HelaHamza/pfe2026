const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV = {
  CRITICAL: { solid: "var(--sev-critical)", track: "var(--sev-critical-bg)" },
  HIGH:     { solid: "var(--sev-high)",     track: "var(--sev-high-bg)" },
  MEDIUM:   { solid: "var(--sev-medium)",   track: "var(--sev-medium-bg)" },
  LOW:      { solid: "var(--sev-low)",      track: "var(--sev-low-bg)" },
};

export default function SigmaSeverityBars({ byLevel }) {
  const counts = ORDER.map((k) => ({
    key: k, count: byLevel?.[k] ?? byLevel?.[k.toLowerCase()] ?? 0,
  }));
  const total = counts.reduce((s, c) => s + c.count, 0);
  const max   = Math.max(...counts.map((c) => c.count), 1);

  return (
    <section className="card">
      <div className="card__head">
        <h3 className="card__title">Sigma — répartition par sévérité</h3>
        <span className="card__hint">
          {total.toLocaleString("fr-FR")} alerte{total > 1 ? "s" : ""}
        </span>
      </div>

      {total === 0 ? (
        <div style={{ textAlign: "center", padding: "40px 0",
                      color: "var(--text-faint)", fontSize: 12 }}>
          Aucune alerte Sigma sur ce run
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "var(--sp-3)" }}>
          {counts.map(({ key, count }) => (
            <div key={key} style={{ display: "flex", alignItems: "center", gap: "var(--sp-3)" }}>
              <span style={{ width: 64, fontSize: 11, fontWeight: 600,
                             color: SEV[key].solid, textTransform: "uppercase",
                             letterSpacing: ".04em", fontFamily: "var(--font-mono)" }}>
                {key}
              </span>
              <div style={{ flex: 1, height: 8, background: SEV[key].track,
                            borderRadius: "var(--r-sm)", overflow: "hidden" }}>
                <div style={{ width: `${(count / max) * 100}%`, height: "100%",
                              background: SEV[key].solid, transition: "width .4s var(--ease)" }} />
              </div>
              <span style={{ width: 32, textAlign: "right", fontSize: 12, fontWeight: 600,
                             color: count === 0 ? "var(--text-faint)" : "var(--text)",
                             fontVariantNumeric: "tabular-nums", fontFamily: "var(--font-mono)" }}>
                {count}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}