import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { authService } from '../services/api'
import AuthShell from '../components/AuthShell.jsx'
import styles from './LoginPage.module.css'

export default function LoginPage() {
  const navigate  = useNavigate()
  const { login } = useAuth()

  // "credentials" | "otp"
  const [step,     setStep]     = useState('credentials')
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [code,     setCode]     = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState('')

  /* ── Étape 1 : valide credentials → envoie OTP ── */
  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!email || !password) { setError('Please fill in all fields.'); return }

    setLoading(true)
    try {
      await authService.login(email, password)   // retourne { message: "OTP sent" }
      setStep('otp')
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid credentials. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  /* ── Étape 2 : vérifie OTP → JWT ── */
  async function handleVerifyOtp(e) {
    e.preventDefault()
    setError('')
    if (code.length !== 6) { setError('Please enter the 6-digit code.'); return }

    setLoading(true)
    try {
      const data = await authService.verifyOtp(email, code)
      login(data.access_token, data.user)
      navigate('/home', { replace: true })
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid or expired code.')
    } finally {
      setLoading(false)
    }
  }

  const getStrength = () => {
    if (password.length > 12) return { label: 'Strong',    level: 4 }
    if (password.length > 8)  return { label: 'Good',      level: 3 }
    if (password.length > 4)  return { label: 'Weak',      level: 2 }
    if (password.length > 0)  return { label: 'Too short', level: 1 }
    return { label: '', level: 0 }
  }
  const strength = getStrength()

  return (
    <AuthShell>
      <div className={styles.card}>
        <div className={styles.statusBadge}>
          <span className={styles.dotGreen} />
          <span>All systems operational</span>
        </div>

        {/* ════════════ ÉTAPE 1 : credentials ════════════ */}
        {step === 'credentials' && (
          <>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Operator sign-in</h2>
              <p className={styles.cardSub}>Authenticate to access the threat console.</p>
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
                <label htmlFor="email">
                  <span>Email</span>
                  <span className={styles.labelHint}>required</span>
                </label>
                <div className={styles.inputWrap}>
                  <svg className={styles.inputIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                  </svg>
                  <input id="email" type="email" value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="operator@domain.com"
                    autoComplete="username"
                    className={styles.input}
                  />
                </div>
              </div>

              <div className={styles.field}>
                <label htmlFor="password">
                  <span>Password</span>
                  <a href="/forgot-password" className={styles.forgot}>Forgot?</a>
                </label>
                <div className={styles.inputWrap}>
                  <svg className={styles.inputIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                  </svg>
                  <input id="password" type={showPw ? 'text' : 'password'} value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••"
                    autoComplete="current-password"
                    className={styles.input}
                  />
                  <button type="button" className={styles.togglePw}
                    onClick={() => setShowPw((v) => !v)}
                    aria-label="Toggle password visibility"
                  >
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

              <div className={styles.mfa}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>
                </svg>
                <span>A verification code will be sent to your email</span>
              </div>

              <button type="submit" className={styles.submitBtn} disabled={loading}>
                {loading ? <span className={styles.spinner} /> : null}
                {loading ? 'Sending code…' : 'Continue'}
                {!loading && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                  </svg>
                )}
              </button>

              <p className={styles.signupLink}>
                Need an operator account? <a href="/signup">Request access →</a>
              </p>
            </form>
          </>
        )}

        {/* ════════════ ÉTAPE 2 : OTP ════════════ */}
        {step === 'otp' && (
          <>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Two-factor verification</h2>
              <p className={styles.cardSub}>
                Enter the 6-digit code sent to<br />
                <strong>{email}</strong>
              </p>
            </div>

            <form onSubmit={handleVerifyOtp} noValidate>
              {error && (
                <div className={styles.alert} role="alert">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  {error}
                </div>
              )}

              <div className={styles.field}>
                <label htmlFor="code">Verification code</label>
                <div className={styles.inputWrap}>
                  <svg className={styles.inputIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>
                  </svg>
                  <input
                    id="code"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000000"
                    autoFocus
                    autoComplete="one-time-code"
                    className={`${styles.input} ${styles.otpInput}`}
                  />
                </div>
              </div>

              <button type="submit" className={styles.submitBtn} disabled={loading}>
                {loading ? <span className={styles.spinner} /> : null}
                {loading ? 'Verifying…' : 'Verify & Sign in'}
                {!loading && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                  </svg>
                )}
              </button>

              <button type="button" className={styles.backBtn}
                onClick={() => { setStep('credentials'); setCode(''); setError('') }}
              >
                ← Back to sign-in
              </button>
            </form>
          </>
        )}
      </div>
    </AuthShell>
  )
}