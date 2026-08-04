import { useEffect } from 'react'
import { severity, neutral, status } from '../../../theme/colors'
import { formatDate, timeAgo, formatDuration } from '../../../utils/formatters'

export default function LastAnalysisModal({ report, stats, onClose, onLaunchNew }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  if (!report) return null
  const { started_at, finished_at, status: rStatus, analysis_id } = report

  // Câblage sur ReportStats (contrat actuel).
  const s = stats || report.stats || {}
  const critical = (s.cnn_critical ?? 0) + (s.sigma_critical ?? 0)
  const kpis = [
    { label: 'Anomalies AE', value: (s.cnn_episodes  ?? 0).toLocaleString('fr-FR'), color: '#185FA5' },
    { label: 'Alertes Sigma', value: (s.sigma_alerts  ?? 0).toLocaleString('fr-FR'), color: '#534AB7' },
    { label: 'Critiques',     value: critical.toLocaleString('fr-FR'),               color: severity.CRITICAL.bgStrong },
    { label: 'À réviser',     value: (s.cnn_to_review ?? 0).toLocaleString('fr-FR'), color: status.warning },
  ]

  const statusColor = rStatus === 'completed' ? status.ok
                    : rStatus === 'partial'   ? status.warning
                    : status.error
  const statusLabel = rStatus === 'completed' ? 'Analyse terminée'
                    : rStatus === 'partial'   ? 'Analyse partielle'
                    : 'Échouée'

  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(15,23,42,0.55)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '1rem', backdropFilter: 'blur(2px)',
    }}>
      <div onClick={(e) => e.stopPropagation()} style={{
        background: '#fff', borderRadius: 14, padding: '1.5rem',
        width: '100%', maxWidth: 500,
        border: `1px solid ${neutral.border}`,
        fontFamily: "'Inter', system-ui, sans-serif",
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              fontSize: 11, fontWeight: 500, color: statusColor,
              background: `${statusColor}18`, borderRadius: 6,
              padding: '3px 10px', marginBottom: 8,
            }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor }} />
              {statusLabel}
            </div>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 600, color: neutral.text }}>
              Dernière analyse
            </h2>
            <p style={{ margin: '4px 0 0', fontSize: 13, color: neutral.textMuted }}>
              {formatDate(finished_at)} · {timeAgo(finished_at)}
            </p>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: 20, color: neutral.textFaint, lineHeight: 1, padding: 4,
          }}>✕</button>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: '1rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#475569', background: neutral.bgMuted, borderRadius: 6, padding: '4px 10px' }}>
            ⏱ {formatDuration(started_at, finished_at)}
          </span>
          {analysis_id && (
            <span style={{ fontSize: 12, color: '#475569', background: neutral.bgMuted, borderRadius: 6, padding: '4px 10px' }}>
              # {analysis_id.slice(0, 8)}
            </span>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: '1rem' }}>
          {kpis.map((k) => (
            <div key={k.label} style={{ background: neutral.bgAlt, borderRadius: 8, padding: '10px 8px', textAlign: 'center' }}>
              <p style={{ margin: 0, fontSize: 11, color: neutral.textMuted, marginBottom: 4 }}>{k.label}</p>
              <p style={{ margin: 0, fontSize: 18, fontWeight: 600, color: k.color }}>{k.value}</p>
            </div>
          ))}
        </div>

        <div style={{ borderTop: `1px solid ${neutral.border}`, marginBottom: '1rem' }} />

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{
            background: '#fff', color: '#374151',
            border: '1px solid #d1d5db', borderRadius: 8,
            padding: '8px 16px', fontSize: 13, cursor: 'pointer',
          }}>
            Voir le dashboard
          </button>
          <button onClick={() => { onClose(); onLaunchNew() }} style={{
            background: '#185FA5', color: '#fff', border: 'none',
            borderRadius: 8, padding: '8px 16px',
            fontSize: 13, fontWeight: 500, cursor: 'pointer',
          }}>
            ▶ Nouvelle analyse
          </button>
        </div>
      </div>
    </div>
  )
}