// Badge de sévérité : vocabulaire fermé du backend → libellé + couleur.
const SEV = {
  critical: { label: 'Critique', color: 'var(--down)' },
  high:     { label: 'Élevée',   color: 'var(--warn)' },
  medium:   { label: 'Moyenne',  color: 'var(--accent)' },
  low:      { label: 'Faible',   color: 'var(--text-faint)' },
}

function SeverityBadge({ level }) {
  const s = SEV[level] || SEV.low
  return (
    <span className="sev-badge" style={{
      background: s.color, color: '#fff',
      padding: '2px 8px', borderRadius: 999,
      fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap',
    }}>
      {s.label}
    </span>
  )
}

// Score d'anomalie : erreur de reconstruction max de l'épisode, rapportée au
// seuil GPD-POT de la source. « 1.4× le seuil » = combien l'épisode dépasse la
// ligne d'alerte — la mesure du « à quel point c'est anormal ».
function AnomalyScore({ score, threshold }) {
  if (score == null) return <span className="cell">—</span>
  const ratio = threshold ? score / threshold : null
  return (
    <div style={{ lineHeight: 1.3 }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
        {Number(score).toFixed(2)}
      </span>
      {ratio != null && (
        <span style={{
          display: 'block', fontSize: 11, color: 'var(--text-faint)',
        }}>
          {ratio.toFixed(1)}× le seuil
        </span>
      )}
    </div>
  )
}

export default function PendingSection({ data }) {
  const rows = data.results || []
  if (rows.length === 0) {
    return (
      <div className="ai-dash__empty">
        Aucun cas incertain sur la dernière analyse. Tout a été tranché
        automatiquement.
      </div>
    )
  }

  const when = (iso) => (iso ? new Date(iso).toLocaleString('fr-FR') : '—')

  return (
    <div className="table-wrap">
      <table className="dtable">
        <thead>
          <tr>
            <th>Sévérité</th>
            <th>Score d'anomalie</th>
            <th>Technique (MITRE)</th>
            <th>Source</th>
            <th>Machine</th>
            <th>Date de l'événement</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="cell"><SeverityBadge level={r.severity} /></td>
              <td className="cell">
                <AnomalyScore
                  score={r.expert?.score_max}
                  threshold={r.expert?.threshold}
                />
              </td>
              <td className="cell">{r.tactic || '—'}</td>
              <td className="cell">{r.log_source || '—'}</td>
              <td className="cell">{r.host || '—'}</td>
              <td className="cell" style={{ whiteSpace: 'nowrap' }}>
                {when(r.event_time)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}