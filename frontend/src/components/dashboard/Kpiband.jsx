import { severity, neutral } from "../../theme/colors";

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

export default function KpiBand({ stats }) {
  // Câblage sur ReportStats (contrat actuel) :
  //   critical = sévérités critiques des DEUX branches
  //   ae       = anomalies AE CONFIRMÉES (true_positive) → cohérent avec le
  //              tableau qui n'affiche que les TP. Le total brut avant triage
  //              reste visible dans le panneau « Triage CNN → LLM ».
  //   toReview = uncertain / fail-open → déportés vers l'Expert AI
  const critical = (stats?.cnn_critical ?? 0) + (stats?.sigma_critical ?? 0);
  const sigma    = stats?.sigma_alerts  ?? 0;
  const ae       = stats?.cnn_kept      ?? 0;   // TP uniquement
  const toReview = stats?.cnn_to_review ?? 0;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "1.4fr 1fr 1fr 1fr",
      gap: 10,
      padding: "16px 0",
    }}>
      {/* <CriticalCard count={critical} /> */}
      <StatCard
        label="Alertes Sigma"
        value={sigma}
        hint={sigma > 0 ? "Règles déclenchées" : "Aucune règle déclenchée"}
      />
      <StatCard
        label="Anomalies AE"
        value={ae}
        hint={ae > 0 ? "Confirmées par le LLM (TP)" : "Aucune anomalie confirmée"}
      />
      <StatCard
        label="À réviser (Expert AI)"
        value={toReview}
        hint={toReview > 0 ? "Épisodes incertains · déportés" : "Rien à réviser"}
      />
    </div>
  );
}