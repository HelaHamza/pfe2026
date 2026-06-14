import { useState } from 'react'
import { authService } from '../services/api'
import AuthShell from '../components/AuthShell.jsx'
import styles from './LoginPage.module.css'

export default function ForgotPasswordPage() {
  const [email,   setEmail]   = useState('')
  const [sent,    setSent]    = useState(false)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!email) { setError('Please enter your email.'); return }

    setLoading(true)
    try {
      await authService.requestPasswordReset(email)
      setSent(true)
    } catch {
      setSent(true)   // anti-enumeration: never reveal whether the email exists
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell>
      <div className={styles.card}>
        <div className={styles.statusBadge}>
          <span className={styles.dotGreen} />
          <span>Account recovery</span>
        </div>

        {sent ? (
          <>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Check your inbox</h2>
              <p className={styles.cardSub}>
                If an account matches that address, a reset link is on its way. It expires in 60 minutes.
              </p>
            </div>
            <div className={styles.mfa}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
              </svg>
              <span>Didn't get it? Check your spam folder, or try again in a minute.</span>
            </div>
            <p className={styles.signupLink}><a href="/login">← Back to sign-in</a></p>
          </>
        ) : (
          <>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Reset access</h2>
              <p className={styles.cardSub}>Enter your email and we'll send you a reset link.</p>
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

              <div className={styles.field}>
                <label htmlFor="email"><span>Email</span><span className={styles.labelHint}>required</span></label>
                <div className={styles.inputWrap}>
                  <svg className={styles.inputIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                  </svg>
                  <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                    placeholder="operator@domain.com" autoComplete="username" className={styles.input} />
                </div>
              </div>

              <button type="submit" className={styles.submitBtn} disabled={loading}>
                {loading ? <span className={styles.spinner} /> : null}
                {loading ? 'Sending…' : 'Send reset link'}
              </button>

              <p className={styles.signupLink}>Remembered it? <a href="/login">Back to sign-in →</a></p>
            </form>
          </>
        )}
      </div>
    </AuthShell>
  )
}