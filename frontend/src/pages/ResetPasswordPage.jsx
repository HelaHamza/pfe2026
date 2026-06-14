import { useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { authService } from '../services/api'
import AuthShell from '../components/AuthShell.jsx'
import styles from './LoginPage.module.css'

export default function ResetPasswordPage() {
  const [params]  = useSearchParams()
  const navigate  = useNavigate()
  const token     = params.get('token')

  const [password, setPassword] = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState('')

  const getStrength = () => {
    if (password.length > 12) return { label: 'Strong', level: 4 }
    if (password.length > 8)  return { label: 'Good',   level: 3 }
    if (password.length > 4)  return { label: 'Weak',   level: 2 }
    if (password.length > 0)  return { label: 'Too short', level: 1 }
    return { label: '', level: 0 }
  }
  const strength = getStrength()

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (password.length < 6) { setError('Password must be at least 6 characters.'); return }
    if (password !== confirm) { setError('Passwords do not match.'); return }

    setLoading(true)
    try {
      await authService.confirmPasswordReset(token, password)
      navigate('/login?reset=success', { replace: true })
    } catch (err) {
      setError(err.response?.data?.detail || 'This link is invalid or has expired. Request a new one.')
    } finally {
      setLoading(false)
    }
  }

  // Guard: link opened without a token
  if (!token) {
    return (
      <AuthShell>
        <div className={styles.card}>
          <div className={styles.statusBadge}><span className={styles.dotGreen} /><span>Account recovery</span></div>
          <div className={styles.cardHeader}>
            <h2 className={styles.cardTitle}>Invalid link</h2>
            <p className={styles.cardSub}>This reset link is incomplete or malformed.</p>
          </div>
          <p className={styles.signupLink}><a href="/forgot-password">Request a new link →</a></p>
        </div>
      </AuthShell>
    )
  }

  return (
    <AuthShell>
      <div className={styles.card}>
        <div className={styles.statusBadge}><span className={styles.dotGreen} /><span>Account recovery</span></div>
        <div className={styles.cardHeader}>
          <h2 className={styles.cardTitle}>Set new password</h2>
          <p className={styles.cardSub}>Choose a new password for your account.</p>
        </div>

        <form onSubmit={handleSubmit} noValidate>
          {error && (
            <div className={styles.alert} role="alert">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              {error}
            </div>
          )}

          {/* New password */}
          <div className={styles.field}>
            <label htmlFor="password"><span>New password</span></label>
            <div className={styles.inputWrap}>
              <svg className={styles.inputIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              <input id="password" type={showPw ? 'text' : 'password'} value={password}
                onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••"
                autoComplete="new-password" className={styles.input} />
              <button type="button" className={styles.togglePw} onClick={() => setShowPw(v => !v)} aria-label="Toggle password visibility">
                {showPw ? (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>
                  </svg>
                ) : (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                  </svg>
                )}
              </button>
            </div>
            {password && (
              <div className={styles.strength}>
                <div className={styles.strengthBars}>
                  <span className={strength.level >= 1 ? styles.barOn : ''} />
                  <span className={strength.level >= 2 ? styles.barOn : ''} />
                  <span className={strength.level >= 3 ? styles.barOn : ''} />
                  <span className={strength.level >= 4 ? styles.barOn : ''} />
                </div>
                <span className={styles.strengthLabel}>{strength.label}</span>
              </div>
            )}
          </div>

          {/* Confirm */}
          <div className={styles.field}>
            <label htmlFor="confirm"><span>Confirm password</span></label>
            <div className={styles.inputWrap}>
              <svg className={styles.inputIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              <input id="confirm" type={showPw ? 'text' : 'password'} value={confirm}
                onChange={(e) => setConfirm(e.target.value)} placeholder="••••••••••"
                autoComplete="new-password" className={styles.input} />
            </div>
          </div>

          <button type="submit" className={styles.submitBtn} disabled={loading}>
            {loading ? <span className={styles.spinner} /> : null}
            {loading ? 'Updating…' : 'Update password'}
          </button>

          <p className={styles.signupLink}><a href="/login">← Back to sign-in</a></p>
        </form>
      </div>
    </AuthShell>
  )
}