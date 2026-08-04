/* Répartition des alertes : sans danger vs à vérifier.
   La largeur du segment vert = la part du bruit éliminé. */
export default function TriageFunnel({ funnel }) {
  const { total_episodes, false_positive, uncertain, true_positive } = funnel
  if (!total_episodes) return null

  const pct = (n) => (100 * n) / total_episodes

  const segments = [
    { key: 'fp',  label: 'Sans danger',   n: false_positive, color: 'var(--up)' },
    { key: 'unc', label: 'À vérifier',    n: uncertain,      color: 'var(--warn)' },
    { key: 'tp',  label: 'Menace confirmée', n: true_positive, color: 'var(--accent)' },
  ].filter((s) => s.n > 0)

  return (
    <div style={{ marginBottom: 'var(--sp-5)' }}>
      <div style={{
        fontSize: 13, color: 'var(--text-soft)', marginBottom: 'var(--sp-2)',
      }}>
        {total_episodes} alertes suspectes, triées automatiquement :
      </div>

      <div style={{
        display: 'flex', width: '100%', height: 40,
        borderRadius: 'var(--r-md)', overflow: 'hidden',
        border: '1px solid var(--border)',
      }}>
        {segments.map((s) => (
          <div
            key={s.key}
            title={`${s.label} : ${s.n}`}
            style={{
              width: `${pct(s.n)}%`, background: s.color,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#fff', fontFamily: 'var(--font-mono)',
              fontSize: 14, fontWeight: 600, minWidth: s.n > 0 ? 44 : 0,
            }}
          >
            {pct(s.n) >= 12 ? s.n : ''}
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 'var(--sp-4)', marginTop: 'var(--sp-3)', flexWrap: 'wrap' }}>
        {segments.map((s) => (
          <span key={s.key} style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            fontSize: 13, color: 'var(--text-soft)',
          }}>
            <span style={{ width: 12, height: 12, borderRadius: 3, background: s.color }} />
            {s.label} : {s.n}
          </span>
        ))}
      </div>
    </div>
  )
}