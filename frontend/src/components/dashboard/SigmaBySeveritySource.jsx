import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import { severity, neutral } from '../../theme/colors'

export default function SigmaBySeveritySource({ bySource }) {
  const data = Object.entries(bySource || {}).map(([src, sev]) => ({
    source:   src.toUpperCase(),
    critical: sev.critical ?? 0,
    high:     sev.high     ?? 0,
    medium:   sev.medium   ?? 0,
    low:      sev.low      ?? 0,
  }))

  if (!data.length) return (
    <div style={{
      background: '#fff', border: `1px solid ${neutral.border}`,
      borderRadius: 8, padding: '2rem',
      textAlign: 'center', color: neutral.textFaint, fontSize: 13,
    }}>
      Aucune donnée Sigma par source disponible
    </div>
  )

  return (
    <div style={{
      background: '#fff', border: `1px solid ${neutral.border}`,
      borderRadius: 8, padding: '16px 18px',
    }}>
      <div style={{ marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: neutral.text }}>
          Alertes Sigma par sévérité &amp; source de log
        </h3>
        <p style={{ margin: '4px 0 0', fontSize: 11, color: neutral.textMuted }}>
          Source dérivée depuis le titre de la règle Sigma
        </p>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={neutral.borderSoft} />
          <XAxis dataKey="source" tick={{ fontSize: 12, fill: neutral.textMuted }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fontSize: 11, fill: neutral.textFaint }} axisLine={false} tickLine={false} width={40} />
          <Tooltip
            contentStyle={{ background: '#fff', border: `1px solid ${neutral.border}`, borderRadius: 8, fontSize: 12 }}
            formatter={(v, name) => [v.toLocaleString('fr-FR'), name.charAt(0).toUpperCase() + name.slice(1)]}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} formatter={(v) => v.charAt(0).toUpperCase() + v.slice(1)} />
          <Bar dataKey="critical" stackId="a" fill={severity.CRITICAL.bgStrong} />
          <Bar dataKey="high"     stackId="a" fill={severity.HIGH.bgStrong} />
          <Bar dataKey="medium"   stackId="a" fill={severity.MEDIUM.bgStrong} />
          <Bar dataKey="low"      stackId="a" fill={severity.LOW.bgStrong} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}