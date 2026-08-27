
const SOURCE_COLOR = {
  syslog: "#185FA5",
  auth:   "#7C3AED",
  auditd: "#DC2626",
};
const SOURCE_LABEL = { syslog: "syslog", auth: "auth", auditd: "auditd" };

function fmt(n) {
  return (n ?? 0).toLocaleString("fr-FR");
}

// Anneau de progression — remplace l'ancien pourcentage plat pour "Taux
// d'anomalie global", une proportion (contrairement aux totaux du bandeau KPI).
function RingGauge({ pct, active, label }) {
  const size = 56, stroke = 6, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, pct));
  const offset  = c * (1 - clamped / 100);
  const color   = active ? "var(--accent)" : "var(--text-faint)";
  return (
    <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none"
                stroke="var(--surface-sunk)" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth={stroke}
          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset .4s var(--ease)" }}
        />
      </svg>
      <span style={{
        position: "absolute", inset: 0, display: "flex",
        alignItems: "center", justifyContent: "center",
        fontSize: 10, fontWeight: 700, color: "var(--text)",
        fontVariantNumeric: "tabular-nums", fontFamily: "var(--font-mono)",
      }}>
        {label}
      </span>
    </div>
  );
}

export default function LogSourceActivity({ logsBySource, anomaliesBySource, stats }) {
  const anomSrc = anomaliesBySource || {};
  // Le backend initialise anomalies_by_source à 0 pour chaque source dès qu'il
  // y a des logs → non-vide même sans TP. On peut donc afficher le % (0 % le
  // cas échéant). Un ancien snapshot sans le champ retombe en mode logs-seuls.
  const hasPerSource = Object.keys(anomSrc).length > 0;

  const sources = Array.from(new Set([
    ...Object.keys(logsBySource || {}),
    ...Object.keys(anomSrc),
  ])).sort();

  const totalAnomalies = hasPerSource
    ? Object.values(anomSrc).reduce((s, v) => s + (v || 0), 0)
    : (stats?.cnn_kept ?? 0);   // TP

  // ── Cas : aucune donnée du tout ─────────────────────────────────────────
  if (sources.length === 0) {
    return (
      <div className="card" style={{ minHeight: 180, display: "flex", flexDirection: "column" }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "var(--text)", marginBottom: 14 }}>
          Logs &amp; anomalies AE par type
        </h3>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center",
                      textAlign: "center", color: "var(--text-faint)", fontSize: 12 }}>
          Aucune donnée disponible
          <br />
          <span style={{ fontSize: 10 }}>Lancez une analyse pour voir les statistiques par source</span>
        </div>
      </div>
    );
  }

  const rows = sources.map((src) => {
    const logs      = logsBySource?.[src] ?? 0;
    const anomalies = anomSrc[src] ?? 0;
    const rate      = logs > 0 ? (anomalies / logs) * 100 : 0;
    return { src, logs, anomalies, rate };
  });

  const totalLogs  = rows.reduce((s, r) => s + r.logs, 0);
  const maxLogs    = Math.max(...rows.map((r) => r.logs), 1);
  const maxRate    = Math.max(...rows.map((r) => r.rate), 0.0001);
  const globalRate = totalLogs > 0 ? (totalAnomalies / totalLogs) * 100 : 0;

  // % par source seulement si le backend le fournit ET qu'il y a au moins 1 TP :
  // sinon on dimensionne au volume de logs pour ne pas afficher un panneau plat.
  const rateMode = hasPerSource && totalAnomalies > 0;

  return (
    <div className="card" style={{ display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <div className="card__head">
        <h3 className="card__title">
          Logs &amp; anomalies AE par type
        </h3>
        <span className="card__hint">
          {fmt(totalLogs)} log{totalLogs > 1 ? "s" : ""} · {fmt(totalAnomalies)} anomalie{totalAnomalies > 1 ? "s" : ""}
        </span>
      </div>

      {/* Liste des sources */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center", gap: 12 }}>
        {rows.map(({ src, logs, anomalies, rate }) => {
          const color = SOURCE_COLOR[src] || "var(--text-soft)";
          const label = SOURCE_LABEL[src] || src;
          const pct = rateMode ? (rate / maxRate) * 100 : (logs / maxLogs) * 100;

          return (
            <div key={src} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {/* Ligne 1 : nom + chiffres */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{
                  fontSize: 12, fontWeight: 600, color,
                  textTransform: "uppercase", letterSpacing: "0.04em",
                }}>
                  {label}
                </span>
                <span style={{ fontSize: 11, fontVariantNumeric: "tabular-nums" }}>
                  <strong style={{ color: "var(--text)" }}>{fmt(logs)}</strong>
                  <span style={{ color: "var(--text-faint)" }}> logs</span>
                  {hasPerSource && (
                    <>
                      <span style={{ color: "var(--text-faint)" }}> · </span>
                      <strong style={{ color: anomalies > 0 ? "var(--sev-high)" : "var(--text-faint)" }}>
                        {fmt(anomalies)}
                      </strong>
                      <span style={{ color: "var(--text-faint)" }}> anom · </span>
                      <strong style={{ color: rate > 0 ? color : "var(--text-faint)" }}>
                        {rate.toFixed(2)}%
                      </strong>
                    </>
                  )}
                </span>
              </div>

              {/* Ligne 2 : barre */}
              <div style={{
                height: 6, background: "var(--surface-sunk)",
                borderRadius: 3, overflow: "hidden", position: "relative",
              }}>
                <div style={{
                  width: `${pct}%`, height: "100%", background: color,
                  transition: "width 0.4s ease",
                  opacity: (rateMode ? anomalies > 0 : logs > 0) ? 1 : 0.3,
                }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Message : aucune anomalie AE confirmée sur ce run */}
      {hasPerSource && totalAnomalies === 0 && (
        <div style={{
          marginTop: 12, fontSize: 11, color: "var(--text-soft)",
          background: "var(--surface-sunk)", borderRadius: 6, padding: "8px 10px",
          textAlign: "center",
        }}>
          Aucune anomalie AE confirmée (TP) sur ce run — % à 0 par source.
        </div>
      )}

      {/* Footer : taux d'anomalie global — proportion → anneau, pas un total */}
      {totalLogs > 0 && (
        <div style={{
          marginTop: 14, paddingTop: 14,
          borderTop: "1px solid var(--border)",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          fontSize: 11, color: "var(--text-soft)",
        }}>
          <span>Taux d'anomalie global</span>
          <RingGauge
            pct={globalRate}
            active={totalAnomalies > 0}
            label={`${globalRate.toFixed(2)}%`}
          />
        </div>
      )}
    </div>
  );
}