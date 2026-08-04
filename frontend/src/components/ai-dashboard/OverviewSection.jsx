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

export default function OverviewSection({ data }) {
  const { funnel } = data
  return (
    <>
      <TriageFunnel funnel={funnel} />
      <div className="summary__grid">
        <Kpi label="Alertes suspectes détectées" value={funnel.total_episodes}
             sub="sur la dernière analyse" />
        <Kpi label="Classées sans danger" value={funnel.false_positive}
             sub={`${funnel.noise_reduction_pct}\u00a0% du bruit éliminé`} tone="good" />
        <Kpi label="À vérifier par un analyste" value={funnel.uncertain}
             sub="cas incertains, déférés à un humain"
             tone={funnel.uncertain > 0 ? 'warn' : 'neutral'} />
        <Kpi label="Charge de travail évitée" value={`${funnel.noise_reduction_pct}\u00a0%`}
             sub="d'alertes en moins à traiter" tone="good" />
      </div>
    </>
  )
}