function Kpi({ label, value, sub, tone = 'neutral' }) {
  const color = { good: 'var(--up)', warn: 'var(--warn)', neutral: 'var(--text-faint)' }[tone]
  return (
    <div className="kpi">
      <div className="kpi__label">{label}</div>
      <div className="kpi__value"><span style={{ color }}>{value}</span></div>
      {sub && <div className="kpi__sub">{sub}</div>}
    </div>
  )
}

export default function TriageQualitySection({ data }) {
  const t = data.triage
  if (!t) return null

  const secs = t.elapsed_s != null ? `${Math.round(t.elapsed_s)} s` : '—'

  return (
    <div className="summary__grid">
      <Kpi
        label="Alertes triées automatiquement"
        value={t.n_episodes_in ?? '—'}
        sub="lors de la dernière analyse"
      />
      <Kpi
        label="Bruit éliminé"
        value={t.noise_reduction_pct != null ? `${t.noise_reduction_pct}\u00a0%` : '—'}
        sub="d'alertes inutiles écartées"
        tone="good"
      />
      <Kpi
        label="Transmises à un analyste"
        value={t.n_episodes_to_analyst ?? '—'}
        sub="cas incertains à vérifier"
        tone={(t.n_episodes_to_analyst ?? 0) > 0 ? 'warn' : 'neutral'}
      />
      <Kpi
        label="Temps de traitement"
        value={secs}
        sub="pour analyser toutes les alertes"
      />
    </div>
  )
}