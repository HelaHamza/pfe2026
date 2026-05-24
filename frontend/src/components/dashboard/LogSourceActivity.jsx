// ─────────────────────────────────────────────────────────────────────────────
// src/components/dashboard/LogSourceActivity.jsx
// Affiche "Logs & anomalies AE par type" — barres horizontales par source.
//
// Props :
//   logsBySource     : { syslog: 142, auth: 38, auditd: 2547 }
//   anomaliesBySource: { auditd: 58, syslog: 5, auth: 0 }
//
// Comportement :
//   - Liste toutes les sources présentes dans les 2 props (union)
//   - Affiche le nombre de logs analysés
//   - Affiche le nombre d'anomalies AE détectées
//   - Calcule un taux d'anomalie (anomalies / logs)
//   - Barre de progression proportionnelle (max = source avec le + d'anomalies)
//   - Si les 2 props sont vides → état "Aucune donnée"
// ─────────────────────────────────────────────────────────────────────────────

import { severity, neutral } from "../../theme/colors";

// Couleur par source (cohérent avec le reste du dashboard)
const SOURCE_COLOR = {
  syslog: "#185FA5",  // bleu — système/kernel/réseau
  auth:   "#7C3AED",  // violet — authentification
  auditd: "#DC2626",  // rouge — sécurité/audit
};

const SOURCE_LABEL = {
  syslog: "syslog",
  auth:   "auth",
  auditd: "auditd",
};

function fmt(n) {
  return (n ?? 0).toLocaleString("fr-FR");
}

export default function LogSourceActivity({ logsBySource, anomaliesBySource }) {
  // Union des sources des 2 props (au cas où une source n'a pas de logs OU pas d'anomalies)
  const sources = Array.from(
    new Set([
      ...Object.keys(logsBySource || {}),
      ...Object.keys(anomaliesBySource || {}),
    ])
  ).sort();

  // ── Cas : aucune donnée ─────────────────────────────────────────────────
  if (sources.length === 0) {
    return (
      <div style={{
        background:   neutral.bg,
        border:       `1px solid ${neutral.border}`,
        borderRadius: 8,
        padding:      "16px 18px",
        minHeight:    180,
      }}>
        <h3 style={{
          margin: 0, fontSize: 13, fontWeight: 600,
          color: neutral.text, marginBottom: 14,
        }}>
          Logs &amp; anomalies AE par type
        </h3>
        <div style={{
          textAlign: "center", padding: "32px 0",
          color: neutral.textFaint, fontSize: 12,
        }}>
          Aucune donnée disponible
          <br />
          <span style={{ fontSize: 10 }}>Lancez une analyse pour voir les statistiques par source</span>
        </div>
      </div>
    );
  }

  // Données par source
  const rows = sources.map((src) => {
    const logs      = logsBySource?.[src]      ?? 0;
    const anomalies = anomaliesBySource?.[src] ?? 0;
    const rate      = logs > 0 ? (anomalies / logs) * 100 : 0;
    return { src, logs, anomalies, rate };
  });

  const totalLogs      = rows.reduce((s, r) => s + r.logs,      0);
  const totalAnomalies = rows.reduce((s, r) => s + r.anomalies, 0);
  const maxAnomalies   = Math.max(...rows.map((r) => r.anomalies), 1);

  return (
    <div style={{
      background:   neutral.bg,
      border:       `1px solid ${neutral.border}`,
      borderRadius: 8,
      padding:      "16px 18px",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "baseline", marginBottom: 14,
      }}>
        <h3 style={{
          margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text,
        }}>
          Logs &amp; anomalies AE par type
        </h3>
        <span style={{ fontSize: 11, color: neutral.textFaint }}>
          {fmt(totalLogs)} log{totalLogs > 1 ? "s" : ""} · {fmt(totalAnomalies)} anomalie{totalAnomalies > 1 ? "s" : ""}
        </span>
      </div>

      {/* Liste des sources */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {rows.map(({ src, logs, anomalies, rate }) => {
          const color   = SOURCE_COLOR[src] || neutral.textMuted;
          const label   = SOURCE_LABEL[src] || src;
          const pct     = (anomalies / maxAnomalies) * 100;
          const hasData = logs > 0 || anomalies > 0;

          return (
            <div key={src} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {/* Ligne 1 : nom + chiffres */}
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
              }}>
                <span style={{
                  fontSize: 12, fontWeight: 600, color,
                  textTransform: "uppercase", letterSpacing: "0.04em",
                }}>
                  {label}
                </span>
                <span style={{
                  fontSize: 11, color: hasData ? neutral.text : neutral.textFaint,
                  fontVariantNumeric: "tabular-nums",
                }}>
                  <strong style={{ color: neutral.text }}>{fmt(logs)}</strong>
                  <span style={{ color: neutral.textFaint }}> logs · </span>
                  <strong style={{ color: anomalies > 0 ? severity.HIGH.bgStrong : neutral.textFaint }}>
                    {fmt(anomalies)}
                  </strong>
                  <span style={{ color: neutral.textFaint }}> anomalie{anomalies > 1 ? "s" : ""}</span>
                  {logs > 0 && (
                    <span style={{ color: neutral.textFaint, marginLeft: 8 }}>
                      ({rate.toFixed(2)}%)
                    </span>
                  )}
                </span>
              </div>

              {/* Ligne 2 : barre */}
              <div style={{
                height: 6, background: neutral.bgAlt,
                borderRadius: 3, overflow: "hidden", position: "relative",
              }}>
                <div style={{
                  width:      `${pct}%`,
                  height:     "100%",
                  background: color,
                  transition: "width 0.4s ease",
                  opacity:    hasData ? 1 : 0.3,
                }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer : taux global */}
      {totalLogs > 0 && (
        <div style={{
          marginTop:   14,
          paddingTop:  12,
          borderTop:   `1px solid ${neutral.borderSoft}`,
          display:     "flex",
          justifyContent: "space-between",
          fontSize:    11,
          color:       neutral.textMuted,
        }}>
          <span>Taux d'anomalie global</span>
          <strong style={{
            color: neutral.text,
            fontVariantNumeric: "tabular-nums",
          }}>
            {((totalAnomalies / totalLogs) * 100).toFixed(2)}%
          </strong>
        </div>
      )}
    </div>
  );
}