const HP_ROWS = [
  { key: "latent_dim",      label: "Latent dim" },
  { key: "batch_size",      label: "Batch size" },
  { key: "learning_rate",   label: "Learning rate" },
  { key: "weight_decay",    label: "Weight decay" },
  { key: "epochs_max",      label: "Epochs max" },
  { key: "epochs_trained",  label: "Epochs réalisés" },
  { key: "total_params",    label: "Paramètres" },
  { key: "train_duration_s",label: "Durée (s)" },
]

export default function HyperparamsTable({ hyperparameters }) {
  if (!hyperparameters || hyperparameters.length === 0) return null

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 14 }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #E0E0E0", textAlign: "left" }}>
            <th style={{ padding: "8px 12px" }}>Hyperparamètre</th>
            {hyperparameters.map((h) => (
              <th key={h.version} style={{ padding: "8px 12px" }}>{h.version}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {HP_ROWS.map((row) => (
            <tr key={row.key} style={{ borderBottom: "1px solid #F0F0F0" }}>
              <td style={{ padding: "8px 12px", fontWeight: 500 }}>{row.label}</td>
              {hyperparameters.map((h) => (
                <td key={h.version + row.key} style={{ padding: "8px 12px" }}>
                  {h[row.key] != null ? String(h[row.key]) : "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}