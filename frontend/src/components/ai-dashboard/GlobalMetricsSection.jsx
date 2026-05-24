import { fmt } from '../../hooks/metrics'
import GlobalMetricsTable from './GlobalMetricsTable'

/* LIGNE 1 — Métriques globales du modèle.
   Combine : table métriques (precision/recall/f1/auc/val-loss avec tendances),
   timing d'inférence (global + par source), robustesse (mean ± std, CV%). */

const ROB_METRICS = [
  { key: 'precision', label: 'Précision' },
  { key: 'recall',    label: 'Rappel' },
  { key: 'f1',        label: 'F1' },
  { key: 'auc_roc',   label: 'AUC-ROC' },
]

function RobustnessTable({ robustness }) {
  if (!robustness?.length) return null
  // On affiche la dernière version (la robustesse se lit version par version)
  const latest = robustness[robustness.length - 1]

  return (
    <table className="dtable dtable--compact">
      <thead>
        <tr>
          <th>Métrique</th>
          <th className="th--num">Moyenne</th>
          <th className="th--num">Écart-type</th>
          <th className="th--num">CV %</th>
        </tr>
      </thead>
      <tbody>
        {ROB_METRICS.map((m) => {
          const r = latest[m.key] || {}
          const stable = typeof r.cv_pct === 'number' && r.cv_pct < 2
          return (
            <tr key={m.key}>
              <td className="cell cell--head">{m.label}</td>
              <td className="cell cell--num">{fmt(r.mean, 4)}</td>
              <td className="cell cell--num">{fmt(r.std, 4)}</td>
              <td className="cell cell--num" style={{ color: stable ? 'var(--up)' : 'var(--warn)' }}>
                {r.cv_pct != null ? `${fmt(r.cv_pct, 2)}` : '—'}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function TimingTable({ timing }) {
  if (!timing?.length) return null
  const latest = timing[timing.length - 1]
  const bySource = latest.by_source || {}

  return (
    <table className="dtable dtable--compact">
      <thead>
        <tr>
          <th>Source</th>
          <th className="th--num">Events</th>
          <th className="th--num">Moyenne (ms)</th>
          <th className="th--num">µs / event</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(bySource).map(([src, t]) => (
          <tr key={src}>
            <td className="cell cell--head">{src}</td>
            <td className="cell cell--num">{fmt(t.n_events)}</td>
            <td className="cell cell--num">{fmt(t.mean_ms, 3)}</td>
            <td className="cell cell--num">{fmt(t.per_us, 2)}</td>
          </tr>
        ))}
        <tr className="dtable__total">
          <td className="cell cell--head">Global</td>
          <td className="cell cell--num">—</td>
          <td className="cell cell--num">{fmt(latest.total_ms, 3)}</td>
          <td className="cell cell--num">{fmt(latest.per_event_us, 2)}</td>
        </tr>
      </tbody>
    </table>
  )
}

export default function GlobalMetricsSection({ globalMetrics, robustness, timing }) {
  return (
    <div className="gsection">
      <GlobalMetricsTable rows={globalMetrics} />

      <div className="gsection__split">
        <div className="gsection__block">
          <h3 className="subhead"><i className="ti ti-clock" aria-hidden="true" /> Temps d'inférence</h3>
          <TimingTable timing={timing} />
        </div>
        <div className="gsection__block">
          <h3 className="subhead"><i className="ti ti-activity" aria-hidden="true" /> Robustesse (runs répétés)</h3>
          <RobustnessTable robustness={robustness} />
          <p className="subnote">CV % faible = métrique stable d'un run à l'autre.</p>
        </div>
      </div>
    </div>
  )
}