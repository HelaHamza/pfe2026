import { fmt, fmtPct, fmtDelta, prettyAttack } from '../../hooks/metrics'

/* Une carte KPI. trend: 'up' | 'down' | 'warn' | 'neutral' */
function Kpi({ label, value, sub, delta, trend = 'neutral', emphasis }) {
  const trendColor = {
    up: 'var(--up)', down: 'var(--down)', warn: 'var(--warn)', neutral: 'var(--text-faint)',
  }[trend]

  return (
    <div className="kpi" data-emphasis={emphasis ? 'true' : undefined}>
      <div className="kpi__label">{label}</div>
      <div className="kpi__value">
        <span>{value}</span>
        {delta != null && (
          <span className="kpi__delta" style={{ color: trendColor }}>
            {trend === 'up' ? '▲' : trend === 'down' ? '▼' : ''} {delta}
          </span>
        )}
      </div>
      {sub && <div className="kpi__sub" style={emphasis ? { color: trendColor } : undefined}>{sub}</div>}
    </div>
  )
}

export default function SummaryBanner({ summary }) {
  if (!summary) return null

  const { mcc, fpr, macroRecall, worstAttack, fp, globalRecall, latest } = summary

  // Verdict : le coeur du diagnostic ML.
  const macroVal = macroRecall.value
  let verdict, verdictTone
  if (macroVal != null && macroVal < 0.6) {
    verdict =
      `Métriques globales excellentes, mais le rappel moyen sur attaques réelles n'est que de ${fmtPct(macroVal)}. ` +
      `Le modèle laisse passer la majorité des attaques de type « ${worstAttack ? prettyAttack(worstAttack.name) : '—'} ». ` +
      `Priorité : améliorer la détection par attaque, pas les métriques agrégées.`
    verdictTone = 'warn'
  } else if (macroVal != null && macroVal < 0.85) {
    verdict = `Détection correcte mais perfectible : rappel moyen par attaque de ${fmtPct(macroVal)}.`
    verdictTone = 'neutral'
  } else {
    verdict = `Modèle robuste : rappel moyen par attaque de ${fmtPct(macroVal)}, faux positifs maîtrisés.`
    verdictTone = 'up'
  }

  const mccTrend = mcc.delta == null ? 'neutral' : mcc.delta > 0 ? 'up' : mcc.delta < 0 ? 'down' : 'neutral'
  const macroTrend = macroRecall.delta == null ? 'neutral' : macroRecall.delta > 0 ? 'up' : 'down'

  return (
    <div className="summary">
      <div className="summary__grid">
        <Kpi
          label="MCC global"
          value={fmt(mcc.value, 3)}
          sub="qualité globale (déséquilibre-robuste)"
          delta={mcc.delta != null ? fmtDelta(mcc.delta, 3) : null}
          trend={mccTrend}
        />
        <Kpi
          label="Rappel moyen / attaque"
          value={fmtPct(macroRecall.value)}
          sub="moyenne macro sur types d'attaque"
          delta={macroRecall.delta != null ? `${(macroRecall.delta * 100).toFixed(1)} pt` : null}
          trend={macroTrend}
          emphasis={macroRecall.value != null && macroRecall.value < 0.6}
        />
        <Kpi
          label="Taux de faux positifs"
          value={fmtPct(fpr.value, 2)}
          sub={`${fmt(fp.value)} FP sur le trafic normal`}
          trend={fp.value === 0 ? 'up' : 'warn'}
        />
        <Kpi
          label="Pire attaque détectée"
          value={worstAttack ? fmtPct(worstAttack.recall) : '—'}
          sub={worstAttack ? prettyAttack(worstAttack.name) : '—'}
          trend="warn"
          emphasis
        />
      </div>

      <div className="summary__verdict" data-tone={verdictTone}>
        <span className="summary__verdict-dot" />
        <p>{verdict}</p>
      </div>
    </div>
  )
}