import { fmt } from '../../hooks/metrics'

/* Matrice de confusion 2x2 visuelle. cm = {tp, fp, fn, tn}.
   La diagonale (TP/TN) est verte, les erreurs (FP/FN) ambre/rouge. */
function ConfusionGrid({ cm, title }) {
  if (!cm) return null
  const { tp = 0, fp = 0, fn = 0, tn = 0 } = cm
  const total = tp + fp + fn + tn || 1
  const pct = (n) => `${((n / total) * 100).toFixed(1)} %`

  const Cell = ({ value, kind, label }) => (
    <div className="cm__cell" data-kind={kind}>
      <span className="cm__cell-label">{label}</span>
      <span className="cm__cell-value">{fmt(value)}</span>
      <span className="cm__cell-pct">{pct(value)}</span>
    </div>
  )

  return (
    <div className="cm">
      {title && <div className="cm__title">{title}</div>}
      <div className="cm__axis cm__axis--x">
        <span>Prédit : Attaque</span><span>Prédit : Normal</span>
      </div>
      <div className="cm__body">
        <div className="cm__axis cm__axis--y">
          <span>Réel : Attaque</span><span>Réel : Normal</span>
        </div>
        <div className="cm__grid">
          <Cell value={tp} kind="ok"   label="TP" />
          <Cell value={fn} kind="warn" label="FN" />
          <Cell value={fp} kind="bad"  label="FP" />
          <Cell value={tn} kind="ok"   label="TN" />
        </div>
      </div>
    </div>
  )
}

export default function ConfusionMatrices({ separation, bySource, version }) {
  const sep = separation?.length ? separation[separation.length - 1] : null
  const globalCm = sep?.cm

  const sources = bySource ? Object.entries(bySource) : []

  return (
    <div className="cm-section">
      <div className="cm-section__global">
        <ConfusionGrid cm={globalCm} title={`Global · ${version || ''}`} />
      </div>
      {sources.length > 0 && (
        <div className="cm-section__sources">
          {sources.map(([src, series]) => {
            const latest = series[series.length - 1]
            return <ConfusionGrid key={src} cm={latest?.cm} title={src} />
          })}
        </div>
      )}
    </div>
  )
}