import { severity } from '../../../theme/colors'

export default function ErrorBanner({ message }) {
  if (!message) return null
  return (
    <div style={{
      background: severity.CRITICAL.bg, color: severity.CRITICAL.bgStrong,
      padding: '8px 24px', fontSize: 12,
      borderBottom: `1px solid ${severity.CRITICAL.border}`,
    }}>
      ⚠ Erreur : {message}
    </div>
  )
}