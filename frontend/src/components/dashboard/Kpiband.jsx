import { neutral } from "../../theme/colors";

function fmt(n) {
  return (n ?? 0).toLocaleString("fr-FR");
}

function StatCard({ label, value, hint, hintColor }) {
  const isNum   = typeof value === "number";
  const isZero  = isNum ? !value : false;
  const display = isNum ? fmt(value) : value;
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
        {display}
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
  const sigma    = stats?.sigma_alerts  ?? 0;
  const ae       = stats?.cnn_kept      ?? 0;   // TP uniquement (confirmés)
  const toReview = stats?.cnn_to_review ?? 0;   // incertains → Expert IA

  return (
    <div style={{ padding: "16px 0" }}>
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)",
        gap: 10,
      }}>
        <StatCard
          label="Alertes Sigma"
          value={sigma}
          hint={sigma > 0 ? "Signatures connues déclenchées" : "Aucune signature déclenchée"}
        />
        <StatCard
          label="Anomalies AE"
          value={ae}
          hint={ae > 0 ? "Confirmées par le LLM (vrais positifs)" : "Aucune anomalie confirmée"}
        />
        {/* <StatCard
          label="À réviser (Expert IA)"
          value={toReview}
          hint={toReview > 0 ? "Cas incertains → dashboard Expert IA" : "Rien à réviser"}
        /> */}
      </div>

      {/* Légende du pipeline — rend la bande auto-explicative pour le jury */}
      <div style={{
        marginTop: 10, fontSize: 11, color: neutral.textMuted, lineHeight: 1.5,
      }}>
        <strong style={{ color: neutral.textMuted }}>Pipeline :</strong>{" "}
        le CNN-AE détecte les anomalies, le LLM les trie — confirmés → SOC ·
        incertains → Expert IA · faux positifs → écartés.
      </div>
    </div>
  );
}