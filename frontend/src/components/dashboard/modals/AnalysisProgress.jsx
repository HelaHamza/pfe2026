import { neutral } from '../../../theme/colors'

export default function AnalysisProgress({ pct, logs }) {
  const r = 52
  const circ = 2 * Math.PI * r
  const dash = circ - (pct / 100) * circ

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 2000,
      background: 'rgba(15,23,42,0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      backdropFilter: 'blur(4px)',
    }}>
      <div style={{
        background: '#fff', borderRadius: 16,
        padding: '2rem 2.5rem', width: 420,
        border: `1px solid ${neutral.border}`,
        textAlign: 'center',
      }}>
        <div style={{ position: 'relative', width: 120, height: 120, margin: '0 auto 1.25rem' }}>
          <svg width="120" height="120" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="60" cy="60" r={r} fill="none" stroke={neutral.border} strokeWidth="8" />
            <circle
              cx="60" cy="60" r={r}
              fill="none" stroke="#185FA5" strokeWidth="8" strokeLinecap="round"
              strokeDasharray={circ} strokeDashoffset={dash}
              style={{ transition: 'stroke-dashoffset 0.6s ease' }}
            />
          </svg>
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center',
          }}>
            <span style={{ fontSize: 22, fontWeight: 700, color: neutral.text }}>{pct}%</span>
            <span style={{ fontSize: 10, color: neutral.textMuted, marginTop: 2 }}>
              {pct < 100 ? 'en cours' : 'terminé'}
            </span>
          </div>
        </div>

        <h3 style={{ margin: '0 0 6px', fontSize: 16, fontWeight: 600, color: neutral.text }}>
          Analyse en cours...
        </h3>
        <p style={{ margin: '0 0 1.25rem', fontSize: 12, color: neutral.textMuted }}>
          AE + Sigma + LLM — ne fermez pas cette fenêtre
        </p>

        <div style={{
          background: '#0f172a', borderRadius: 8,
          padding: '10px 14px', textAlign: 'left',
          minHeight: 80, maxHeight: 120, overflowY: 'auto',
        }}>
          {logs.length === 0 ? (
            <span style={{ color: '#475569', fontSize: 12 }}>Initialisation...</span>
          ) : logs.map((log, i) => (
            <div key={i} style={{
              fontSize: 11,
              color: log.includes('✓') ? '#4ade80'
                   : log.includes('✗') || log.includes('ERREUR') ? '#f87171'
                   : log.includes('[AE]') ? '#60a5fa'
                   : log.includes('[SIGMA]') ? '#c084fc'
                   : log.includes('[FUSION]') ? '#fb923c'
                   : '#94a3b8',
              lineHeight: 1.6,
              fontFamily: 'monospace',
            }}>
              {log}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}