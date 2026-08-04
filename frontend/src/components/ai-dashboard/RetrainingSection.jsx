function Kpi({ label, value, sub, tone = 'neutral' }) {
  const color = { good: 'var(--up)', warn: 'var(--warn)', bad: 'var(--down)', neutral: 'var(--text-faint)' }[tone]
  return (
    <div className="kpi">
      <div className="kpi__label">{label}</div>
      <div className="kpi__value"><span style={{ color }}>{value}</span></div>
      {sub && <div className="kpi__sub">{sub}</div>}
    </div>
  )
}

// Explique le ratio accepté / évalué en une phrase, adaptée au cas.
function acceptanceSub(a) {
  const total = a?.n_total ?? 0
  const accepted = a?.n_accepted ?? 0
  if (total === 0) return 'aucun cycle de ré-entraînement lancé'
  const rate = Math.round((100 * accepted) / total)
  const candidats = `${total} candidat${total > 1 ? 's' : ''} évalué${total > 1 ? 's' : ''}`
  if (accepted === 0) {
    return `${candidats}, aucun validé — le gate a bloqué toute régression`
  }
  return `${candidats}, ${accepted} validé${accepted > 1 ? 's' : ''} (${rate} % accepté)`
}

export default function RetrainingSection({ data }) {
  const { last, golden, acceptance } = data
  const accepted = last?.accepted

  const nAccepted = acceptance?.n_accepted ?? 0
  const nTotal = acceptance?.n_total ?? 0

  // Attaques de référence détectées : candidat vs version en production.
  const nCandidate = golden?.detected
    ? Object.values(golden.detected).filter(Boolean).length
    : null
  const nTotalAtt = golden?.n_incidents ?? null
  const nBaseline = golden?.baseline
    ? Object.values(golden.baseline).filter(Boolean).length
    : null
  const regressed = nCandidate != null && nBaseline != null && nCandidate < nBaseline

  return (
    <>
      <div className="summary__grid">
        <Kpi
          label="Nouvelle version du modèle"
          value={accepted ? 'Validée' : 'Refusée'}
          sub={accepted
            ? 'promue en production'
            : 'bloquée par le contrôle qualité — l\u2019ancienne version, plus fiable, reste en place'}
          tone={accepted ? 'good' : 'bad'}
        />
        <Kpi
          label="Détection : candidat vs production"
          value={nCandidate != null ? `${nCandidate} / ${nTotalAtt}` : '—'}
          sub={nBaseline != null
            ? (regressed
                ? `régression : la version en production détecte ${nBaseline} / ${nTotalAtt}`
                : `version en production : ${nBaseline} / ${nTotalAtt}`)
            : 'sur les attaques de référence (golden set)'}
          tone={regressed ? 'warn' : 'good'}
        />
        <Kpi
          label="Versions mises en production"
          value={`${nAccepted} sur ${nTotal}`}
          sub={acceptanceSub(acceptance)}
          tone="neutral"
        />
      </div>

      {/* Lecture du ratio : ce que signifie chaque nombre, en clair. */}
      {nTotal > 0 && (
        <p className="retrain__legend">
          <strong>{nTotal}</strong> = version{nTotal > 1 ? 's' : ''} candidate{nTotal > 1 ? 's' : ''} testée{nTotal > 1 ? 's' : ''} par le contrôle qualité ·{' '}
          <strong>{nAccepted}</strong> = version{nAccepted > 1 ? 's' : ''} ayant réussi les tests et mise{nAccepted > 1 ? 's' : ''} en production.
        </p>
      )}

      {/* Verdict en clair : POURQUOI, et pourquoi c'est un bon signe. */}
      {last?.reason && (
        <p className={`retrain__reason retrain__reason--${accepted ? 'ok' : 'block'}`}>
          {last.reason}
          {!accepted && (
            <span className="retrain__reason-note">
              {' '}Le contrôle qualité automatique a empêché une version moins
              fiable d'atteindre la production.
            </span>
          )}
        </p>
      )}
    </>
  )
}