function Kpi({ label, value, sub, tone = 'neutral' }) {
  const color = { good: 'var(--up)', warn: 'var(--warn)', neutral: 'var(--text)' }[tone]
  return (
    <div className="kpi">
      <div className="kpi__label">{label}</div>
      <div className="kpi__value"><span style={{ color }}>{value}</span></div>
      {sub && <div className="kpi__sub">{sub}</div>}
    </div>
  )
}

/* Couverture de la couche d'explication LLM (mode explication seule).
   Le CNN LÈVE les anomalies (toutes conservées) ; le LLM tente d'EXPLIQUER
   chacune. Trois comptes + le coût :
     • total    = anomalies levées par le modèle       (prioritization.total_episodes)
     • expliquées = total − fail-open                  (calculé)
     • non expliquées = pannes LLM, conservées par sécurité (prioritization.n_fail_open)
     • temps    = durée de traitement LLM              (triage.elapsed_s)
   Invariant : expliquées + non expliquées = total. */
export default function AnalysisSection({ overview, triage }) {
  const prio = overview.prioritization || {}
  const total = prio.total_episodes ?? 0
  const failOpen = prio.n_fail_open ?? 0
  const explained = Math.max(total - failOpen, 0)
  const secs = triage?.triage?.elapsed_s != null
    ? `${Math.round(triage.triage.elapsed_s)} s` : null

  return (
    <div className="summary__grid">
      <Kpi
        label="Anomalies levées par le modèle"
        value={total}
        sub="détectées par le CNN, toutes conservées"
      />
      <Kpi
        label="Anomalies expliquées"
        value={explained}
        sub="analysées et priorisées par le LLM"
        tone="good"
      />
      <Kpi
        label="Anomalies non expliquées"
        value={failOpen}
        sub={`${prio.fail_open_pct ?? 0}\u00a0% — panne LLM (fail-open), conservées par sécurité`}
        tone={failOpen > 0 ? 'warn' : 'good'}
      />
      <Kpi
        label="Temps de traitement LLM"
        value={secs || '—'}
        sub={`pour ${total} anomalies`}
        tone="neutral"
      />
    </div>
  )
}