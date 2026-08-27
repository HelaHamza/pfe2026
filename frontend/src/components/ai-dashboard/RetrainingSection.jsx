function Kpi({ label, value, sub, tone = 'neutral', emphasis = false }) {
  const color = { good: 'var(--up)', warn: 'var(--warn)', bad: 'var(--down)', neutral: 'var(--text)' }[tone]
  return (
    <div className="kpi" data-emphasis={emphasis ? tone : undefined}>
      <div className="kpi__label">{label}</div>
      <div className="kpi__value"><span style={{ color }}>{value}</span></div>
      {sub && <div className="kpi__sub">{sub}</div>}
    </div>
  )
}

// Explique le ratio promu / évalué en une phrase, adaptée au cas.
function acceptanceSub(a) {
  const total = a?.n_total ?? 0
  const accepted = a?.n_accepted ?? 0
  if (total === 0) return 'aucun cycle de ré-entraînement lancé'
  const candidats = `${total} candidat${total > 1 ? 's' : ''} évalué${total > 1 ? 's' : ''}`
  if (accepted === 0) {
    return `${candidats}, aucun promu — le gate a bloqué toute régression`
  }
  const rate = Math.round((100 * accepted) / total)
  return `${candidats}, ${accepted} promu${accepted > 1 ? 's' : ''} (${rate} % accepté)`
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
        {/* Verdict qualité = LE signal du jury → seule carte mise en avant */}
        <Kpi
          label="Verdict du contrôle qualité"
          value={accepted ? 'Validée' : 'Refusée'}
          sub={accepted
            ? 'nouvelle version promue en production'
            : 'nouvelle version bloquée — l\u2019ancienne, plus fiable, reste en place'}
          tone={accepted ? 'good' : 'bad'}
          emphasis
        />
        <Kpi
          label="Attaques de référence retrouvées par le candidat"
          value={nCandidate != null ? `${nCandidate} / ${nTotalAtt}` : '—'}
          sub={nBaseline != null
            ? (regressed
                ? `${nCandidate} des ${nTotalAtt} attaques du golden set — la version en production les retrouve toutes (${nBaseline}/${nTotalAtt})`
                : `${nCandidate} des ${nTotalAtt} attaques du golden set retrouvées`)
            : `sur ${nTotalAtt ?? '—'} attaques de référence (golden set)`}
          tone={regressed ? 'warn' : 'good'}
        />
        <Kpi
          label="Candidats promus en production"
          value={`${nAccepted} sur ${nTotal}`}
          sub={acceptanceSub(acceptance)}
          tone="neutral"
        />
      </div>

      {/* Lecture des nombres, en clair. */}
      {nTotal > 0 && (
        <p className="retrain__legend">
          <strong>{nTotalAtt ?? '—'}</strong> = attaques connues du golden set ·{' '}
          <strong>{nCandidate ?? '—'}</strong> = celles que le nouveau modèle a su retrouver ·{' '}
          <strong>{nTotal}</strong> = version{nTotal > 1 ? 's' : ''} candidate{nTotal > 1 ? 's' : ''} évaluée{nTotal > 1 ? 's' : ''} par le contrôle qualité ·{' '}
          <strong>{nAccepted}</strong> = celle{nAccepted > 1 ? 's' : ''} réellement promue{nAccepted > 1 ? 's' : ''} en production.
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