import { fmt } from '../../hooks/metrics'

/* Seuils de décision par source/contexte + stats de nettoyage du dataset.
   Affiché pour la dernière version sélectionnée. */

function ThresholdsTable({ thresholds }) {
  if (!thresholds?.length) return null
  const latest = thresholds[thresholds.length - 1]?.thresholds || {}
  const sources = Object.keys(latest)
  if (!sources.length) return null

  // contextes possibles (business / night / other)
  const contexts = Array.from(
    new Set(sources.flatMap((s) => Object.keys(latest[s] || {})))
  )

  return (
    <table className="dtable dtable--compact">
      <thead>
        <tr>
          <th>Source</th>
          {contexts.map((c) => <th key={c} className="th--num">{c}</th>)}
        </tr>
      </thead>
      <tbody>
        {sources.map((s) => (
          <tr key={s}>
            <td className="cell cell--head">{s}</td>
            {contexts.map((c) => (
              <td key={s + c} className="cell cell--num">{fmt(latest[s]?.[c], 4)}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function CleaningTable({ cleaning }) {
  if (!cleaning?.length) return null
  const latest = cleaning[cleaning.length - 1]?.cleaning_stats || {}
  const sources = Object.keys(latest)
  if (!sources.length) return null

  return (
    <table className="dtable dtable--compact">
      <thead>
        <tr>
          <th>Source</th>
          <th className="th--num">Avant</th>
          <th className="th--num">Exclus</th>
          <th className="th--num">Après</th>
          <th className="th--num">% exclus</th>
        </tr>
      </thead>
      <tbody>
        {sources.map((s) => {
          const c = latest[s] || {}
          const pct = c.before ? (c.excluded / c.before) * 100 : null
          return (
            <tr key={s}>
              <td className="cell cell--head">{s}</td>
              <td className="cell cell--num">{fmt(c.before)}</td>
              <td className="cell cell--num" style={{ color: 'var(--warn)' }}>{fmt(c.excluded)}</td>
              <td className="cell cell--num">{fmt(c.after)}</td>
              <td className="cell cell--num">{pct != null ? `${fmt(pct, 1)} %` : '—'}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

export default function ThresholdsCleaningSection({ thresholds, cleaning }) {
  return (
    <div className="gsection__split">
      <div className="gsection__block">
        <h3 className="subhead"><i className="ti ti-adjustments-horizontal" aria-hidden="true" /> Seuils de décision</h3>
        <ThresholdsTable thresholds={thresholds} />
        <p className="subnote">Seuil de reconstruction au-delà duquel un événement est jugé anormal, par source et contexte horaire.</p>
      </div>
      <div className="gsection__block">
        <h3 className="subhead"><i className="ti ti-filter" aria-hidden="true" /> Nettoyage du jeu d'entraînement</h3>
        <CleaningTable cleaning={cleaning} />
        <p className="subnote">Événements exclus de l'entraînement (probables anomalies dans le trafic « normal »).</p>
      </div>
    </div>
  )
}