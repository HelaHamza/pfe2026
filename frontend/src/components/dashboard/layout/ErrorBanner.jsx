import { severity } from '../../../theme/colors'

// variant "error"   → échec réseau ou run failed (rouge)
// variant "warning" → run partiel : une branche a échoué mais les résultats
//                     réussis restent affichés (ambre)
export default function ErrorBanner({ message, variant = 'error' }) {
  if (!message) return null
  const warn = variant === 'warning'
  const sev  = warn ? severity.MEDIUM : severity.CRITICAL
  return (
    <div style={{
      background: sev.bg, color: sev.bgStrong,
      padding: '8px 24px', fontSize: 12,
      borderBottom: `1px solid ${sev.border}`,
    }}>
      ⚠ {warn ? 'Analyse partielle : ' : 'Erreur : '}{message}
    </div>
  )
}