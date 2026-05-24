import { fmt, fmtPct, mcc, fpr } from '../../hooks/metrics'

const SRC_METRICS = [
  { key: 'precision', label: 'Précision' },
  { key: 'recall',    label: 'Rappel' },
  { key: 'f1',        label: 'F1' },
  { key: 'auc_roc',   label: 'AUC-ROC' },
]

const val = (cell) => (cell && typeof cell.value === 'number' ? cell.value : null)

export default function MetricsBySourceCards({ bySource, version }) {
  if (!bySource) return null
  const sources = Object.entries(bySource)
  if (!sources.length) return null

  return (
    <div>
      <div className="src-caption">
        Métriques de la version <span className="badge badge--accent">{version || 'courante'}</span>
      </div>
      <div className="src-grid">
        {sources.map(([src, series]) => {
          const latest = series[series.length - 1]
          const precision = val(latest?.precision)
          const weak = precision != null && precision < 0.8
          const fp = latest?.false_positives
          const fn = latest?.false_negatives
          const cm = latest?.cm || {}
          const srcMcc = mcc(cm)
          const srcFpr = fpr(cm)

          return (
            <div key={src} className="src-card" data-weak={weak ? 'true' : undefined}>
              <div className="src-card__head">
                <span className="src-card__name">{src}</span>
                {weak && <span className="badge badge--down">précision faible</span>}
              </div>
              <table className="src-card__table">
                <tbody>
                  {SRC_METRICS.map((sm) => (
                    <tr key={sm.key}>
                      <td className="src-card__k">{sm.label}</td>
                      <td className="src-card__v">{fmt(val(latest?.[sm.key]))}</td>
                    </tr>
                  ))}
                  <tr className="src-card__sep"><td colSpan={2} /></tr>
                  <tr>
                    <td className="src-card__k">MCC</td>
                    <td className="src-card__v">{fmt(srcMcc, 3)}</td>
                  </tr>
                  <tr>
                    <td className="src-card__k">FPR</td>
                    <td className="src-card__v">{fmtPct(srcFpr, 2)}</td>
                  </tr>
                  <tr>
                    <td className="src-card__k">Faux positifs</td>
                    <td className="src-card__v" style={{ color: fp > 0 ? 'var(--down)' : 'var(--up)' }}>
                      {fp != null ? fp : '—'}
                    </td>
                  </tr>
                  <tr>
                    <td className="src-card__k">Faux négatifs</td>
                    <td className="src-card__v" style={{ color: fn > 0 ? 'var(--warn)' : 'var(--up)' }}>
                      {fn != null ? fn : '—'}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          )
        })}
      </div>
    </div>
  )
}