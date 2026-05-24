import { fmt } from '../../hooks/metrics'

/* LIGNE 2 — Paramètres & hyperparamètres du modèle.
   Bloc gauche : paramètres structurels (taille, latent, alphas appris).
   Bloc droit  : hyperparamètres d'entraînement (lr, epochs, batch...). */

function MultiVersionRow({ label, versions, get, digits }) {
  return (
    <tr>
      <td className="cell cell--head">{label}</td>
      {versions.map((v) => (
        <td key={v.version + label} className="cell cell--num">{fmt(get(v), digits)}</td>
      ))}
    </tr>
  )
}

export default function ModelConfigSection({ modelInfo, hyperparameters }) {
  if (!hyperparameters?.length) return null
  const mi = modelInfo || []

  const alphaKeys = Array.from(
    new Set(mi.flatMap((m) => Object.keys(m.alphas_learned || {})))
  )

  return (
    <div className="gsection__split">
      {/* --- Paramètres du modèle --- */}
      <div className="gsection__block">
        <h3 className="subhead"><i className="ti ti-cpu" aria-hidden="true" /> Paramètres du modèle</h3>
        <table className="dtable dtable--compact">
          <thead>
            <tr>
              <th>Paramètre</th>
              {mi.map((m) => <th key={m.version} className="th--num">{m.version}</th>)}
            </tr>
          </thead>
          <tbody>
            <MultiVersionRow label="Nombre de paramètres" versions={mi} get={(m) => m.total_params} />
            <MultiVersionRow label="Espace latent (latent_dim)" versions={mi} get={(m) => m.latent_dim} />
            <MultiVersionRow label="Inférence / event (µs)" versions={mi} get={(m) => m.per_event_us} digits={2} />
            {alphaKeys.map((ak) => (
              <MultiVersionRow key={ak} label={`α appris · ${ak}`} versions={mi}
                get={(m) => m.alphas_learned?.[ak]} digits={4} />
            ))}
          </tbody>
        </table>
      </div>

      {/* --- Hyperparamètres d'entraînement --- */}
      <div className="gsection__block">
        <h3 className="subhead"><i className="ti ti-adjustments" aria-hidden="true" /> Hyperparamètres d'entraînement</h3>
        <table className="dtable dtable--compact">
          <thead>
            <tr>
              <th>Hyperparamètre</th>
              {hyperparameters.map((h) => <th key={h.version} className="th--num">{h.version}</th>)}
            </tr>
          </thead>
          <tbody>
            <MultiVersionRow label="Learning rate" versions={hyperparameters} get={(h) => h.learning_rate} />
            <MultiVersionRow label="Batch size" versions={hyperparameters} get={(h) => h.batch_size} />
            <MultiVersionRow label="Weight decay" versions={hyperparameters} get={(h) => h.weight_decay} />
            <MultiVersionRow label="Epochs max" versions={hyperparameters} get={(h) => h.epochs_max} />
            <MultiVersionRow label="Epochs réalisés" versions={hyperparameters} get={(h) => h.epochs_trained} />
            <MultiVersionRow label="Patience (early stop)" versions={hyperparameters} get={(h) => h.patience} />
            <MultiVersionRow label="Durée entraînement (s)" versions={hyperparameters} get={(h) => h.train_duration_s} digits={2} />
            <MultiVersionRow label="Device" versions={hyperparameters} get={(h) => h.device} />
          </tbody>
        </table>
      </div>
    </div>
  )
}