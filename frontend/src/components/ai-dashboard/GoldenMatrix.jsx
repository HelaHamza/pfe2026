/* Golden set (domaine C) : détection par attaque, candidat vs baseline.
   Une ligne = une attaque. On voit d'un coup les RÉGRESSIONS : là où la
   baseline détectait (✓) mais le candidat rate (✗) → deux colonnes qui
   divergent. C'est la preuve visuelle du rejet du gate. */
function Mark({ ok }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      width: 24, height: 24, borderRadius: 'var(--r-sm)',
      background: ok ? 'var(--up-bg)' : 'var(--down-bg)',
      color: ok ? 'var(--up)' : 'var(--down)',
      fontWeight: 700, fontSize: 14,
    }}>
      {ok ? '✓' : '✗'}
    </span>
  )
}

export default function GoldenMatrix({ golden }) {
  if (!golden) return null
  const { detected, baseline, regressions } = golden
  const attacks = Object.keys(baseline || detected || {})
  if (attacks.length === 0) return null

  const isRegression = (a) => (regressions || []).includes(a)

  return (
    <div className="table-wrap">
      <table className="dtable dtable--compact">
        <thead>
          <tr>
            <th>Attaque du golden set</th>
            <th style={{ textAlign: 'center' }}>Baseline déployée</th>
            <th style={{ textAlign: 'center' }}>Candidat</th>
            <th style={{ textAlign: 'center' }}>Statut</th>
          </tr>
        </thead>
        <tbody>
          {attacks.map((a) => {
            const reg = isRegression(a)
            return (
              <tr key={a}>
                <td className="cell cell--head" style={{ fontFamily: 'var(--font-mono)' }}>{a}</td>
                <td className="cell" style={{ textAlign: 'center' }}>
                  <Mark ok={baseline?.[a]} />
                </td>
                <td className="cell" style={{ textAlign: 'center' }}>
                  <Mark ok={detected?.[a]} />
                </td>
                <td className="cell" style={{ textAlign: 'center' }}>
                  {reg
                    ? <span className="badge badge--down">Régression</span>
                    : <span className="badge badge--accent">OK</span>}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}