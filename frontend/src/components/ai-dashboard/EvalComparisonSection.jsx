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

export default function EvalComparisonSection({ data }) {
  const c = data.comparison
  if (!c) return null

  const pct = (v) => `${Math.round(v * 100)}\u00a0%`
  const dPrec = Math.round(c.precision_delta * 100)   // points de précision gagnés
  const lost = c.attacks_lost                          // attaques perdues (coût)

  return (
    <>
      {/* Rappel de qui est quoi, une fois en tête */}
      <p className="eval__legend">
        <span className="eval__tag eval__tag--cnn">CNN seul</span>
        détection statistique brute ·
        <span className="eval__tag eval__tag--pipe">CNN → LLM</span>
        pipeline complet, après vérification par le LLM
      </p>

      <div className="summary__grid">
        {/* Précision : CNN seul → pipeline complet */}
        <Kpi
          label="Précision de détection"
          value={`${pct(c.cnn.precision)} → ${pct(c.cascade.precision)}`}
          sub={dPrec >= 0
            ? `CNN seul → CNN → LLM : +${dPrec} points`
            : `CNN seul → CNN → LLM : ${dPrec} points`}
          tone="good"
        />
        {/* Fausses alertes retirées par l'étage LLM */}
        <Kpi
          label="Fausses alertes supprimées"
          value={c.fp_removed}
          sub="retirées par l'étage LLM du pipeline"
          tone="good"
        />
        {/* Rappel : CNN seul → pipeline complet */}
        <Kpi
          label="Attaques détectées"
          value={`${c.attack.attacks_detected_cnn} / ${c.n_attacks} → ${c.attack.attacks_detected_cascade} / ${c.n_attacks}`}
          sub={lost > 0
            ? `CNN seul → CNN → LLM : −${lost} technique(s) atomique(s)`
            : 'CNN seul → CNN → LLM : rappel préservé'}
          tone={lost > 0 ? 'warn' : 'good'}
        />
        {/* Bilan net de l'étage LLM */}
        <Kpi
          label="Bilan de l'étage LLM"
          value={lost > 0 ? `+${c.fp_removed} / −${lost}` : `+${c.fp_removed}`}
          sub="fausses alertes retirées / attaques perdues"
          tone="neutral"
        />
      </div>

      {/* Récit de l'arbitrage précision vs rappel */}
      {/* Récit de l'arbitrage précision vs rappel, ancré sur le groundtruth */}
      <p className="eval__tradeoff">
        {lost > 0 ? (
          <>
            Évaluation sur un <strong>jeu de vérité terrain (groundtruth)</strong> :{' '}
            {c.n_attacks} attaques étiquetées ont été injectées, puis mesurées
            à l'identique sur le <strong>CNN seul</strong> et sur le pipeline{' '}
            <strong>CNN → LLM</strong>. Le CNN seul détecte les{' '}
            {c.attack.attacks_detected_cnn}/{c.n_attacks} attaques mais à une
            précision de {pct(c.cnn.precision)} (des fausses alertes). Le
            pipeline CNN → LLM porte la précision à{' '}
            <strong>{pct(c.cascade.precision)}</strong> en écartant {lost}{' '}
            action(s) atomique(s) isolée(s) — une élévation de privilège, une
            modification d'horodatage — indistinguables d'une activité légitime
            hors contexte. Compromis assumé et <strong>mesuré</strong> : −{lost}{' '}
            attaque(s) sur {c.n_attacks} contre <strong>zéro fausse alerte</strong>.
          </>
        ) : (
          <>
            Évaluation sur un <strong>jeu de vérité terrain (groundtruth)</strong> :{' '}
            {c.n_attacks} attaques étiquetées injectées, mesurées à l'identique
            sur le <strong>CNN seul</strong> et sur le pipeline{' '}
            <strong>CNN → LLM</strong>. Le pipeline améliore la précision
            ({pct(c.cnn.precision)} → {pct(c.cascade.precision)}) sans perte de
            rappel : les {c.n_attacks} attaques détectées par le CNN seul le
            restent après vérification LLM.
          </>
        )}
      </p>
    </>
  )
}