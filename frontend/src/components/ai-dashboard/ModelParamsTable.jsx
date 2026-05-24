function fmt(v) {
  if (v == null) return "—"
  if (typeof v === "number") return Number.isInteger(v) ? v.toLocaleString() : v
  return String(v)
}

export default function ModelParamsTable({ modelInfo, bySource }) {
  if (!modelInfo || modelInfo.length === 0) return null

  const ROWS = [
    { label: "Espace latent (latent_dim)", get: (m) => m.latent_dim },
    { label: "Learning rate", get: (m) => m.learning_rate },
    { label: "Paramètres du modèle", get: (m) => m.total_params },
    { label: "Inférence / event (µs)", get: (m) => m.per_event_us },
    { label: "Faux positifs (global)", get: (m) => m.global_fp },
    { label: "Faux négatifs (global)", get: (m) => m.global_fn },
    { label: "Alpha auditd", get: (m) => m.alphas_learned?.auditd },
    { label: "Alpha auth",   get: (m) => m.alphas_learned?.auth },
    { label: "Alpha syslog", get: (m) => m.alphas_learned?.syslog },
  ]

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 14 }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #E0E0E0", textAlign: "left" }}>
            <th style={{ padding: "8px 12px" }}>Paramètre</th>
            {modelInfo.map((m) => (
              <th key={m.version} style={{ padding: "8px 12px", textAlign: "right" }}>{m.version}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ROWS.map((row, i) => (
            <tr key={i} style={{ borderBottom: "1px solid #F0F0F0" }}>
              <td style={{ padding: "8px 12px", fontWeight: 500 }}>{row.label}</td>
              {modelInfo.map((m) => (
                <td key={m.version + i} style={{ padding: "8px 12px", textAlign: "right" }}>
                  {fmt(row.get(m))}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}