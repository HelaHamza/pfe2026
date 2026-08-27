function fmt(n) {
  return (n ?? 0).toLocaleString("fr-FR");
}

function StatCard({ label, value, hint, hintColor }) {
  const isNum   = typeof value === "number";
  const isZero  = isNum ? !value : false;
  const display = isNum ? fmt(value) : value;
  return (
    <div style={{
      background: "var(--surface-2)",
      border: "1px solid var(--border)",
      borderRadius: "var(--r-md)",
      padding: "var(--sp-3) var(--sp-4)",
      minHeight: 92,
    }}>
      <span style={{
        fontSize: 11, fontWeight: 600, color: "var(--text-soft)",
        textTransform: "uppercase", letterSpacing: "0.06em",
      }}>
        {label}
      </span>
      <div style={{
        fontSize: 26, fontWeight: 600, lineHeight: 1.1, marginTop: 4,
        color: isZero ? "var(--text-faint)" : "var(--text)",
        fontVariantNumeric: "tabular-nums",
      }}>
        {display}
      </div>
      {hint && (
        <div style={{
          fontSize: 11, marginTop: 4,
          color: hintColor || "var(--text-faint)",
        }}>
          {hint}
        </div>
      )}
    </div>
  );
}

export default function KpiBand({ stats }) {
  const sigma    = stats?.sigma_alerts  ?? 0;
  const ae       = stats?.cnn_kept      ?? 0;   // TP uniquement (confirmés)
  const toReview = stats?.cnn_to_review ?? 0;   // incertains → Expert IA

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(2, 1fr)",
      gap: "var(--sp-3)",
      marginBottom: "var(--sp-4)",
    }}>
      <StatCard
        label="Alertes Sigma"
        value={sigma}
        hint={sigma > 0 ? "Signatures connues déclenchées" : "Aucune signature déclenchée"}
      />
      <StatCard
        label="Anomalies AE"
        value={ae}
        hint={ae > 0 ? "déclanchées par le modèle (vrais positifs)" : "Aucune anomalie confirmée"}
      />
      {/* <StatCard
        label="À réviser (Expert IA)"
        value={toReview}
        hint={toReview > 0 ? "Cas incertains → dashboard Expert IA" : "Rien à réviser"}
      /> */}
    </div>
  );
}