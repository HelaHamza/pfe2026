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

/* Capacité de détection du MODÈLE EN PRODUCTION (CNN seul) — option B.
   En mode explication seule, le LLM n'écarte plus rien : le détecteur, c'est
   le CNN. Deux métriques à granularités différentes (méthodologie assumée) :
   précision au niveau ALERTE, rappel au niveau ATTAQUE. Consomme
   EvalComparisonResponse { has_data, metrics }. */
export default function EvalComparisonSection({ data }) {
  const m = data.metrics
  if (!m) return null

  const pct = (v) => `${Math.round((v ?? 0) * 100)}\u00a0%`

  return (
    <>
      <div className="summary__grid">
        <Kpi
          label="Précision de détection"
          value={pct(m.precision)}
          sub={`${m.tp} alertes justes sur ${m.n_alerts}`}
          tone="good"
        />
        <Kpi
          label="Rappel de détection"
          value={pct(m.recall)}
          sub={`${m.attacks_detected} attaques détectées sur ${m.n_attacks}`}
          tone="good"
        />
        <Kpi
          label="Attaques manquées"
          value={m.attacks_missed}
          sub="non détectées par le CNN"
          tone={m.attacks_missed > 0 ? 'warn' : 'good'}
        />
        <Kpi
          label="Fausses alertes"
          value={m.fp}
          sub={`sur ${m.n_alerts} alertes levées`}
          tone="neutral"
        />
      </div>

      <p className="eval__tradeoff">
        Un ensemble d'attaques étiquetées a été <strong>injecté</strong> dans
        les logs (jeu de vérité terrain), puis analysé par le{' '}
        <strong>CNN seul</strong> — le détecteur réellement en production, le
        LLM n'écartant aucune alerte.{' '}
        La <strong>précision</strong> est mesurée au niveau des{' '}
        <strong>alertes</strong> : sur les {m.n_alerts} alertes levées, {m.tp}{' '}
        visaient une vraie attaque ({pct(m.precision)}) — elle répond à
        «&nbsp;quand le modèle alerte, a-t-il raison&nbsp;?&nbsp;».{' '}
        Le <strong>rappel</strong> est mesuré au niveau des{' '}
        <strong>attaques</strong> : sur les {m.n_attacks} attaques injectées,{' '}
        {m.attacks_detected} ont été détectées ({pct(m.recall)}) — il répond à
        «&nbsp;combien d'attaques réelles le modèle attrape-t-il&nbsp;?&nbsp;».{' '}
        Les deux sont présentés séparément, à leur granularité propre, plutôt
        que fondus dans un F1 qui mélangerait alertes et attaques.
      </p>
    </>
  )
}