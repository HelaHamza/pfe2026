import { severity, neutral } from "../../theme/colors";

const SOURCE_COLOR = {
  syslog: "#185FA5",
  auth:   "#7C3AED",
  auditd: "#DC2626",
};
const SOURCE_LABEL = { syslog: "syslog", auth: "auth", auditd: "auditd" };

function fmt(n) {
  return (n ?? 0).toLocaleString("fr-FR");
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
      <div style={{
        background: neutral.bg, border: `1px solid ${neutral.border}`,
        borderRadius: 8, padding: "16px 18px", minHeight: 180,
      }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text, marginBottom: 14 }}>
          Logs &amp; anomalies AE par type
        </h3>
        <div style={{ textAlign: "center", padding: "32px 0", color: neutral.textFaint, fontSize: 12 }}>
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
    <div style={{
      background: neutral.bg, border: `1px solid ${neutral.border}`,
      borderRadius: 8, padding: "16px 18px",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "baseline", marginBottom: 14,
      }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text }}>
          Logs &amp; anomalies AE par type
        </h3>
        <span style={{ fontSize: 11, color: neutral.textFaint }}>
          {fmt(totalLogs)} log{totalLogs > 1 ? "s" : ""} · {fmt(totalAnomalies)} anomalie{totalAnomalies > 1 ? "s" : ""}
        </span>
      </div>

      {/* Liste des sources */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {rows.map(({ src, logs, anomalies, rate }) => {
          const color = SOURCE_COLOR[src] || neutral.textMuted;
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
                  <strong style={{ color: neutral.text }}>{fmt(logs)}</strong>
                  <span style={{ color: neutral.textFaint }}> logs</span>
                  {hasPerSource && (
                    <>
                      <span style={{ color: neutral.textFaint }}> · </span>
                      <strong style={{ color: anomalies > 0 ? severity.HIGH.bgStrong : neutral.textFaint }}>
                        {fmt(anomalies)}
                      </strong>
                      <span style={{ color: neutral.textFaint }}> anom · </span>
                      <strong style={{ color: rate > 0 ? color : neutral.textFaint }}>
                        {rate.toFixed(2)}%
                      </strong>
                    </>
                  )}
                </span>
              </div>

              {/* Ligne 2 : barre */}
              <div style={{
                height: 6, background: neutral.bgAlt,
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
          marginTop: 12, fontSize: 11, color: neutral.textMuted,
          background: neutral.bgAlt, borderRadius: 6, padding: "8px 10px",
          textAlign: "center",
        }}>
          Aucune anomalie AE confirmée (TP) sur ce run — % à 0 par source.
        </div>
      )}

      {/* Footer : taux d'anomalie global */}
      {totalLogs > 0 && (
        <div style={{
          marginTop: 14, paddingTop: 12,
          borderTop: `1px solid ${neutral.borderSoft}`,
          display: "flex", justifyContent: "space-between",
          fontSize: 11, color: neutral.textMuted,
        }}>
          <span>Taux d'anomalie global</span>
          <strong style={{ color: neutral.text, fontVariantNumeric: "tabular-nums" }}>
            {globalRate.toFixed(2)}%
          </strong>
        </div>
      )}
    </div>
  );
}