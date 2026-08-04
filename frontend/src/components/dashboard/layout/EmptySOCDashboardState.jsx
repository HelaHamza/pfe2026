// src/components/dashboard/layout/EmptySOCDashboardState.jsx
import { neutral } from '../../../theme/colors'

export default function EmptyDashboardState({ onLaunch }) {
  return (
    <div style={{
      background: '#fff',
      border: `1px dashed ${neutral.border}`,
      borderRadius: 12,
      padding: '48px 24px',
      textAlign: 'center',
      margin: '24px 0',
    }}>
      <div style={{ fontSize: 48, marginBottom: 16 }}>🛡️</div>

      <h2 style={{ margin: '0 0 8px', fontSize: 20, fontWeight: 600, color: neutral.text }}>
        Bienvenue dans le SOC Dashboard
      </h2>

      <p style={{ margin: '0 auto 24px', maxWidth: 480, fontSize: 14, color: neutral.textMuted, lineHeight: 1.6 }}>
        Aucune analyse n'a encore été lancée. Cliquez ci-dessous pour démarrer
        la détection : le CNN-AE remonte les épisodes anormaux, Sigma couvre les
        signatures connues, et le LLM trie et explique chaque cas avant de le
        rattacher aux techniques MITRE ATT&CK.
      </p>

      <button onClick={onLaunch} style={{
        background: '#185FA5', color: '#fff', border: 'none',
        borderRadius: 8, padding: '12px 24px',
        fontSize: 14, fontWeight: 500, cursor: 'pointer',
      }}>
        ▶ Lancer la première analyse
      </button>

      <div style={{
        marginTop: 32, paddingTop: 24,
        borderTop: `1px solid ${neutral.borderSoft}`,
        display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)',
        gap: 24, maxWidth: 600, margin: '32px auto 0',
        textAlign: 'left',
      }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#378ADD', marginBottom: 4 }}>CNN-AE</div>
          <div style={{ fontSize: 11, color: neutral.textMuted }}>Détection d'anomalies par autoencodeur convolutif</div>
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#7F77DD', marginBottom: 4 }}>SIGMA</div>
          <div style={{ fontSize: 11, color: neutral.textMuted }}>Règles de détection sur signatures connues</div>
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#fb923c', marginBottom: 4 }}>LLM</div>
          <div style={{ fontSize: 11, color: neutral.textMuted }}>Triage, explication et vérification des épisodes</div>
        </div>
      </div>
    </div>
  )
}