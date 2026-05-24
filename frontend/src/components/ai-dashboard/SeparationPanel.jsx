import { fmt } from '../../hooks/metrics'

/* Séparation de reconstruction : cœur de la qualité d'un autoencodeur.
   Un ratio MSE attaque/normal élevé = les anomalies sont nettement
   plus mal reconstruites que le trafic normal (= bonne séparation). */

function qualityOf(ratio) {
  if (ratio == null) return null
  if (ratio >= 100) return 'excellent'
  if (ratio >= 20) return 'bon'
  return 'faible'
}

function colorOf(quality) {
  if (quality === 'excellent') return 'var(--up)'
  if (quality === 'bon') return 'var(--warn)'
  if (quality === 'faible') return 'var(--down)'
  return 'var(--border)'
}

export default function SeparationPanel({ separation }) {
  if (!separation?.length) return null
  const latest = separation[separation.length - 1]
  const { mse_normal, mse_attack, mse_ratio } = latest

  const ratio = typeof mse_ratio === 'number' ? mse_ratio : null
  const quality = qualityOf(ratio)
  const color = colorOf(quality)

  return (
    <div className="sep">
      <div className="sep__stats">
        <div className="sep__stat">
          <span className="sep__stat-label">MSE trafic normal</span>
          <span className="sep__stat-value">{fmt(mse_normal, 4)}</span>
        </div>
        <div className="sep__arrow"><i className="ti ti-arrow-right" aria-hidden="true" /></div>
        <div className="sep__stat">
          <span className="sep__stat-label">MSE attaques</span>
          <span className="sep__stat-value">{fmt(mse_attack, 2)}</span>
        </div>
      </div>

      <div className="sep__ratio-card" style={{ borderColor: color }}>
        <span className="sep__ratio-label">Ratio de séparation</span>
        <span className="sep__ratio-value" style={{ color }}>×{fmt(mse_ratio, 1)}</span>
        <span className="sep__ratio-tag" style={{ color }}>séparation {quality || '—'}</span>
      </div>

      <p className="subnote">
        Les attaques sont reconstruites {ratio ? `~${Math.round(ratio)}×` : ''} plus mal que le trafic
        normal : c'est cet écart qui permet la détection par seuil.
      </p>
    </div>
  )
}