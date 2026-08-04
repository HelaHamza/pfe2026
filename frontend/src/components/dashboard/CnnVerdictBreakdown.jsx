import { severity, status as statusColors, neutral } from "../../theme/colors";

// Verdicts du triage LLM (branche CNN). Voir models/enums.py :
//   true_positive  → escaladé vers le SOC
//   uncertain      → déporté vers l'Expert AI (JAMAIS écarté silencieusement)
//   false_positive → bruit écarté (compte dans noise_reduction_pct)
const VERDICTS = [
  { key: "true_positive",  label: "Vrais positifs", hint: "→ SOC",        color: severity.CRITICAL.bgStrong },
  { key: "uncertain",      label: "Incertains",     hint: "→ Expert AI",  color: severity.MEDIUM.bgStrong },
  { key: "false_positive", label: "Faux positifs",  hint: "bruit écarté", color: statusColors.ok },
];

export default function CnnVerdictBreakdown({ byVerdict }) {
  const rows = VERDICTS.map((v) => ({
    ...v,
    count: byVerdict?.[v.key] ?? 0,
  }));
  const total = rows.reduce((s, r) => s + r.count, 0);
  const max   = Math.max(...rows.map((r) => r.count), 1);

  return (
    <div style={{
      background: neutral.bg,
      border: `1px solid ${neutral.border}`,
      borderRadius: 8,
      padding: "16px 18px",
      minHeight: 220,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text }}>
          Triage CNN → LLM
        </h3>
        <span style={{ fontSize: 11, color: neutral.textFaint }}>
          {total.toLocaleString("fr-FR")} épisode{total > 1 ? "s" : ""}
        </span>
      </div>

      {total === 0 ? (
        <div style={{
          fontSize: 12, color: neutral.textFaint,
          textAlign: "center", padding: "40px 0",
        }}>
          Aucun épisode CNN à trier
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {rows.map(({ key, label, hint, count, color }) => {
            const pct = (count / max) * 100;
            return (
              <div key={key} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ width: 118, flexShrink: 0 }}>
                  <div style={{
                    fontSize: 12, fontWeight: 600, color,
                  }}>
                    {label}
                  </div>
                  <div style={{ fontSize: 10, color: neutral.textFaint }}>
                    {hint}
                  </div>
                </div>
                <div style={{ flex: 1, height: 8, background: neutral.bgMuted, borderRadius: 2, overflow: "hidden" }}>
                  <div style={{
                    width: `${pct}%`, height: "100%",
                    background: color,
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
      )}
    </div>
  );
}