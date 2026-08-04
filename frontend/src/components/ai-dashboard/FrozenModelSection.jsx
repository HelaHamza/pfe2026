// Carte ① — Modèle en production : identité + calibration PAR SOURCE.
// Recall/precision N'Y SONT PAS (ils vivent dans « Capacité de détection »,
// seule source à vérité terrain). Consomme FrozenModelResponse.

const fmtDate = (v) => {
  if (!v) return '—'
  const d = new Date(v)
  return isNaN(d) ? '—'
    : d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' })
}
const fmtInt = (v) => (v == null ? '—' : Number(v).toLocaleString('fr-FR'))
const fmtNum = (v, d = 2) => (v == null ? '—' : Number(v).toFixed(d))
const fmtPct = (v) => (v == null ? '—' : `${Number(v).toFixed(2)} %`)

function Kpi({ label, value }) {
  return (
    <div className="fm__kpi">
      <span className="fm__kpi-label">{label}</span>
      <span className="fm__kpi-value">{value}</span>
    </div>
  )
}

export default function FrozenModelSection({ data }) {
  const sources = Object.entries(data.by_source || {})

  return (
    <div className="fm">
      {/* Bandeau identité */}
      <div className="fm__kpis">
        <Kpi
          label="Version du modèle en production"
          value={data.version || 'Version initiale'}
          sub={data.version ? null : 'aucune mise à jour validée à ce jour'}
        />
        <Kpi
          label="Date de mise en production"
          value={fmtDate(data.promoted_at)}
          sub={data.promoted_at ? null : 'modèle de référence, jamais remplacé'}
        />
        <Kpi label="Événements analysés" value={fmtInt(data.total_events)} />
        <Kpi label="Épisodes signalés" value={fmtInt(data.n_alert_episodes)} />
        <Kpi
          label="LLM de vérification"
          value={data.llm_model
            ? `${data.llm_model} · ${data.llm_provider || '?'}`
            : '—'}
        />
      </div>

      {/* Calibration par source (seuils GPD-POT) */}
      <table className="fm__table">
        <thead>
          <tr>
            <th>Source de logs</th>
            <th>Seuil d'alerte (GPD-POT)</th>
            <th>% d'événements alertés</th>
            <th>Volume analysé</th>
            <th>Entraînement / Validation</th>
          </tr>
        </thead>
        <tbody>
          {sources.length === 0 && (
            <tr>
              <td colSpan={5} className="fm__muted">
                Calibration indisponible (rapport d'entraînement absent).
              </td>
            </tr>
          )}
          {sources.map(([src, c]) => (
            <tr key={src}>
              <td className="fm__src">{src}</td>
              <td>{fmtNum(c.threshold, 3)}</td>
              <td>{fmtPct(c.alert_rate_pct)}</td>
              <td>{fmtInt(c.n_test)}</td>
              <td>
                {c.n_train == null && c.n_eval == null
                  ? '—'
                  : `${fmtInt(c.n_train)} / ${fmtInt(c.n_eval)}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Repli : forme de la distribution — justifie le choix GPD-POT */}
      {sources.length > 0 && (
        <details className="fm__details">
          <summary>
            Distribution des scores d'anomalie (justifie le seuil GPD-POT)
          </summary>
          <table className="fm__table">
            <thead>
              <tr>
                <th>Source de logs</th><th>Score médian</th><th>Score p99</th>
                <th>Asymétrie</th><th>Aplatissement</th><th>Période analysée</th>
              </tr>
            </thead>
            <tbody>
              {sources.map(([src, c]) => (
                <tr key={src}>
                  <td className="fm__src">{src}</td>
                  <td>{fmtNum(c.score_median, 4)}</td>
                  <td>{fmtNum(c.score_p99, 4)}</td>
                  <td>{fmtNum(c.score_skew, 2)}</td>
                  <td>{fmtNum(c.score_kurtosis, 1)}</td>
                  <td className="fm__win">
                    {fmtDate(c.window_start)} → {fmtDate(c.window_end)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="fm__note">
            Scores fortement leptokurtiques (kurtosis ≫ 3) et asymétriques à
            droite (skew &gt; 0) : distribution à <strong>queue lourde</strong>.
            Le seuil par théorie des valeurs extrêmes (GPD-POT) est donc
            justifié — un seuil gaussien sous-estimerait la queue et générerait
            des faux positifs.
          </p>
        </details>
      )}

      {data.reason && <p className="fm__reason">{data.reason}</p>}
    </div>
  )
}