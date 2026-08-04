import TriageFunnel from './TriageFunnel'

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

/* Entonnoir du pipeline complet CNN → LLM sur les alertes du dernier run.
   Le CNN LÈVE les alertes brutes ; le LLM les TRIE (sans danger / à vérifier).
   overview = comptes de l'entonnoir ; triage = temps de traitement LLM. */
export default function AnalysisSection({ overview, triage }) {
  const { funnel } = overview
  const secs = triage?.triage?.elapsed_s != null
    ? `${Math.round(triage.triage.elapsed_s)} s` : null

  return (
    <>
      {/* <TriageFunnel funnel={funnel} /> */}

      <div className="summary__grid">
        <Kpi
          label="Alertes levées par le CNN"
          value={funnel.total_episodes}
          sub="anomalies brutes, avant vérification LLM"
        />
        <Kpi
          label="Classées sans danger par le LLM"
          value={funnel.false_positive}
          sub={`${funnel.noise_reduction_pct}\u00a0% du bruit CNN éliminé`}
          tone="good"
        />
        <Kpi
          label="Déférées à un analyste par le LLM"
          value={funnel.uncertain}
          sub="cas jugés incertains, revue humaine"
          tone={funnel.uncertain > 0 ? 'warn' : 'neutral'}
        />
        <Kpi
          label="Temps de traitement LLM"
          value={secs || '—'}
          sub={`${funnel.total_episodes} alertes triées automatiquement`}
          tone="neutral"
        />
      </div>
    </>
  )
}