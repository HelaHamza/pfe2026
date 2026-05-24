// ─────────────────────────────────────────────────────────────────────────────
// src/components/dashboard/Kpiband.jsx
// Refonte : carte "Critiques" dominante (1.4fr) + zéros déprioritisés en gris
// ─────────────────────────────────────────────────────────────────────────────

import { severity, neutral, status } from "../../theme/colors";

function fmt(n) {
  return (n ?? 0).toLocaleString("fr-FR");
}

// Carte critique — dominante, fond rouge léger, bordure gauche forte
function CriticalCard({ count, unacknowledged }) {
  const isZero = !count;
  return (
    <div style={{
      background: isZero ? neutral.bgAlt : severity.CRITICAL.bg,
      borderLeft: `3px solid ${isZero ? neutral.border : severity.CRITICAL.bgStrong}`,
      borderRadius: "0 8px 8px 0",
      padding: "14px 16px",
      minHeight: 92,
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{
          fontSize: 11, fontWeight: 600,
          color: isZero ? neutral.textFaint : severity.CRITICAL.text,
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          Alertes critiques
        </span>
        <span style={{ fontSize: 14, color: isZero ? neutral.textFaint : severity.CRITICAL.bgStrong }}>⚠</span>
      </div>
      <div style={{
        fontSize: 32, fontWeight: 600, lineHeight: 1.1, marginTop: 4,
        color: isZero ? neutral.textGhost : severity.CRITICAL.text,
        fontVariantNumeric: "tabular-nums",
      }}>
        {fmt(count)}
      </div>
      <div style={{
        fontSize: 11, marginTop: 4,
        color: isZero ? neutral.textFaint : severity.CRITICAL.text,
      }}>
        {isZero
          ? "Aucune alerte critique"
          : unacknowledged
            ? `${unacknowledged} non-acquittée${unacknowledged > 1 ? "s" : ""} · à examiner`
            : "À examiner"}
      </div>
    </div>
  );
}

// Carte secondaire — fond blanc, zéros en gris clair
function StatCard({ label, value, hint, hintColor }) {
  const isZero = !value;
  return (
    <div style={{
      background: neutral.bg,
      border: `1px solid ${neutral.border}`,
      borderRadius: 8,
      padding: "14px 16px",
      minHeight: 92,
    }}>
      <span style={{
        fontSize: 11, fontWeight: 600, color: neutral.textMuted,
        textTransform: "uppercase", letterSpacing: "0.06em",
      }}>
        {label}
      </span>
      <div style={{
        fontSize: 26, fontWeight: 600, lineHeight: 1.1, marginTop: 4,
        color: isZero ? neutral.textGhost : neutral.text,
        fontVariantNumeric: "tabular-nums",
      }}>
        {fmt(value)}
      </div>
      {hint && (
        <div style={{
          fontSize: 11, marginTop: 4,
          color: hintColor || neutral.textFaint,
        }}>
          {hint}
        </div>
      )}
    </div>
  );
}

export default function KpiBand({ stats, logsBySource, attacksBySource }) {
  const critical   = stats?.critical          ?? 0;
  const sigma      = stats?.sigma_alerts      ?? stats?.total_sigma ?? 0;
  const ae         = stats?.ae_anomalies      ?? stats?.total_ae    ?? 0;
  const correlated = stats?.correlated_both   ?? stats?.correlated  ?? 0;
  const unack      = stats?.critical_unacknowledged ?? 0;

  // Si AE > 0 mais correlated = 0 → warning fusion
  const fusionWarning = ae > 0 && sigma > 0 && correlated === 0;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "1.4fr 1fr 1fr 1fr",
      gap: 10,
      padding: "16px 0",
    }}>
      <CriticalCard count={critical} unacknowledged={unack} />
      <StatCard
        label="Alertes Sigma"
        value={sigma}
        hint={sigma > 0 ? "Règles déclenchées" : "Aucune règle déclenchée"}
      />
      <StatCard
        label="Anomalies AE"
        value={ae}
        hint={ae > 0 ? "Détectées par autoencoder" : "Aucune anomalie"}
      />
      <StatCard
        label="Corrélées AE+Σ"
        value={correlated}
        hint={fusionWarning ? "Vérifier fenêtre de fusion" : correlated > 0 ? "Double détection" : "—"}
        hintColor={fusionWarning ? status.warning : undefined}
      />
    </div>
  );
}