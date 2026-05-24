// src/components/dashboard/layout/EmptyDashboardState.jsx
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
        la détection : les modules AE, Sigma et LLM vont analyser vos logs et
        corréler les anomalies avec les techniques MITRE ATT&CK.
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
          <div style={{ fontSize: 12, fontWeight: 600, color: '#185FA5', marginBottom: 4 }}>AE</div>
          <div style={{ fontSize: 11, color: neutral.textMuted }}>Détection d'anomalies par auto-encodeur</div>
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#534AB7', marginBottom: 4 }}>SIGMA</div>
          <div style={{ fontSize: 11, color: neutral.textMuted }}>Règles de corrélation sur signatures connues</div>
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#fb923c', marginBottom: 4 }}>FUSION</div>
          <div style={{ fontSize: 11, color: neutral.textMuted }}>Corrélation AE + Sigma + enrichissement LLM</div>
        </div>
      </div>
    </div>
  )
}