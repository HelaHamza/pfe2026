import { fmt } from '../../hooks/metrics'

const METRICS = [
  { key: 'precision',     label: 'Précision' },
  { key: 'recall',        label: 'Rappel (global)' },
  { key: 'f1_score',      label: 'F1-Score' },
  { key: 'auc_roc',       label: 'AUC-ROC' },
  { key: 'auc_pr',        label: 'AUC-PR' },
  { key: 'best_val_loss', label: 'Val Loss', lowerBetter: true },
]

function TrendCell({ cell, digits }) {
  if (!cell || cell.value == null) return <td className="cell cell--num">—</td>
  const color = cell.trend === 'up' ? 'var(--up)'
    : cell.trend === 'down' ? 'var(--down)' : 'var(--text-faint)'
  const arrow = cell.trend === 'up' ? '▲' : cell.trend === 'down' ? '▼' : ''

  return (
    <td className="cell cell--num">
      <span className="cell__value">{fmt(cell.value, digits)}</span>
      {cell.delta != null && cell.trend !== 'new' && Math.abs(cell.delta) > 1e-9 && (
        <span className="cell__delta" style={{ color }}>
          {arrow} {cell.delta > 0 ? '+' : ''}{fmt(cell.delta, digits)}
        </span>
      )}
      {cell.trend === 'new' && <span className="badge badge--new">nouveau</span>}
    </td>
  )
}

export default function GlobalMetricsTable({ rows }) {
  if (!rows?.length) return null
  return (
    <div className="table-wrap">
      <table className="dtable">
        <thead>
          <tr>
            <th>Métrique</th>
            {rows.map((r) => <th key={r.version} className="th--num">{r.version}</th>)}
          </tr>
        </thead>
        <tbody>
          {METRICS.map((m) => (
            <tr key={m.key}>
              <td className="cell cell--head">{m.label}</td>
              {rows.map((r) => (
                <TrendCell key={r.version + m.key} cell={r[m.key]} digits={m.key === 'best_val_loss' ? 6 : 4} />
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}