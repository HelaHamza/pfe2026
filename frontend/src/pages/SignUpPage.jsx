import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authService } from '../services/api.js'
import styles from './SignUpPage.module.css'

const SPECIALTIES = [
  {
    value: 'ia_user',
    label: 'IA User',
    desc: 'ML model analyst',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z"/>
        <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z"/>
      </svg>
    ),
  },
  {
    value: 'soc_user',
    label: 'SOC User',
    desc: 'Security operator',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>
    ),
  },
]

export default function SignUpPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({
    first_name: '', last_name: '', email: '',
    password: '', phone: '', sex: '', specialty: 'ia_user',
  })
  const [showPw, setShowPw]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const [success, setSuccess] = useState(false)
  const [errors, setErrors]   = useState({})

  function handleChange(e) {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }))
    setErrors(er => ({ ...er, [e.target.name]: '' }))
    setError('')
  }

  function validate() {
    const err = {}
    if (!form.first_name.trim()) err.first_name = 'Required'
    if (!form.last_name.trim())  err.last_name  = 'Required'
    if (!form.email.trim())      err.email      = 'Required'
    if (form.password.length < 6) err.password  = 'At least 6 characters'
    return err
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const err = validate()
    if (Object.keys(err).length) { setErrors(err); return }
    setLoading(true)
    try {
      await authService.signup(form)
      setSuccess(true)
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // Password strength
  const getStrength = () => {
    if (form.password.length > 12) return { label: 'Strong',    level: 4 }
    if (form.password.length > 8)  return { label: 'Good',      level: 3 }
    if (form.password.length > 4)  return { label: 'Weak',      level: 2 }
    if (form.password.length > 0)  return { label: 'Too short', level: 1 }
    return { label: '', level: 0 }
  }
  const strength = getStrength()

  if (success) return (
    <div className={styles.page}>
      <aside className={styles.sidebar}>
        <SidebarContent />
      </aside>
      <main className={styles.main}>
        <div className={styles.successCard}>
          <div className={styles.successIcon}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          </div>
          <div className={styles.statusBadge}>
            <span className={styles.dotGreen} />
            <span>Request submitted</span>
          </div>
          <h2 className={styles.successTitle}>Registration submitted</h2>
          <p className={styles.successText}>
            Your operator account is pending admin approval. You'll receive an
            email at <span className={styles.successEmail}>{form.email || 'your address'}</span> once
            it's been reviewed.
          </p>
          <button className={styles.backBtn} onClick={() => navigate('/login')}>
            <span>Back to sign-in</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
            </svg>
          </button>
        </div>
      </main>
    </div>
  )

  return (
    <div className={styles.page}>
      <aside className={styles.sidebar}>
        <SidebarContent />
      </aside>
      <main className={styles.main}>
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <h1 className={styles.cardTitle}>Create account</h1>
            <p className={styles.cardSub}>Request operator access to the threat console.</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <div className={styles.row}>
              <Field
                label="First name"
                name="first_name"
                value={form.first_name}
                onChange={handleChange}
                error={errors.first_name}
                placeholder="Yassine"
              />
              <Field
                label="Last name"
                name="last_name"
                value={form.last_name}
                onChange={handleChange}
                error={errors.last_name}
                placeholder="Benali"
              />
            </div>

            <Field
              label="Email"
              name="email"
              type="email"
              value={form.email}
              onChange={handleChange}
              error={errors.email}
              placeholder="operator@domain.com"
              icon={<EmailIcon />}
            />

            <div className={styles.fieldWrap}>
              <label className={styles.label}>
                <span>Password</span>
                <span className={styles.labelHint}>min. 6 chars</span>
              </label>
              <div className={styles.inputWrap}>
                <span className={styles.inputIcon}><LockIcon /></span>
                <input
                  type={showPw ? 'text' : 'password'}
                  name="password"
                  value={form.password}
                  onChange={handleChange}
                  placeholder="••••••••••"
                  className={`${styles.input} ${styles.inputWithIcon} ${errors.password ? styles.inputError : ''}`}
                />
                <button
                  type="button"
                  className={styles.togglePw}
                  onClick={() => setShowPw(v => !v)}
                  aria-label="Toggle password"
                >
                  {showPw ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>

              {form.password && !errors.password && (
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

              {errors.password && <span className={styles.errorMsg}>{errors.password}</span>}
            </div>

            <div className={styles.row}>
              <Field
                label="Phone (optional)"
                name="phone"
                type="tel"
                value={form.phone}
                onChange={handleChange}
                placeholder="+213 xxx xxx xxx"
              />
              <div className={styles.fieldWrap}>
                <label className={styles.label}>
                  <span>Sex</span>
                  <span className={styles.labelHint}>optional</span>
                </label>
                <select name="sex" value={form.sex} onChange={handleChange} className={styles.select}>
                  <option value="">Select…</option>
                  <option value="male">Male</option>
                  <option value="female">Female</option>
                  <option value="other">Prefer not to say</option>
                </select>
              </div>
            </div>

            <div className={styles.fieldWrap}>
              <label className={styles.label}>
                <span>Role</span>
                <span className={styles.labelHint}>select one</span>
              </label>
              <div className={styles.specialtyGroup}>
                {SPECIALTIES.map(s => (
                  <label
                    key={s.value}
                    className={`${styles.specialtyOption} ${form.specialty === s.value ? styles.specialtyActive : ''}`}
                  >
                    <input
                      type="radio"
                      name="specialty"
                      value={s.value}
                      checked={form.specialty === s.value}
                      onChange={handleChange}
                      hidden
                    />
                    <span className={styles.specialtyIcon}>{s.icon}</span>
                    <span className={styles.specialtyLabel}>{s.label}</span>
                    <span className={styles.specialtyDesc}>{s.desc}</span>
                  </label>
                ))}
              </div>
            </div>

            {error && (
              <div className={styles.alert} role="alert">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                {error}
              </div>
            )}

            <button type="submit" className={styles.submitBtn} disabled={loading}>
              {loading && <span className={styles.spinner} />}
              {loading ? 'Submitting…' : 'Request access'}
              {!loading && (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                </svg>
              )}
            </button>

            <p className={styles.loginLink}>
              Already have an account? <Link to="/login">Sign in →</Link>
            </p>
          </form>
        </div>
      </main>
    </div>
  )
}

function SidebarContent() {
  return (
    <>
      <div className={styles.gridOverlay} aria-hidden="true" />

      {/* Brand */}
      <div className={styles.sidebarTop}>
        <div className={styles.logoRow}>
          <div className={styles.logoMark}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#052e16" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div>
            <div className={styles.logoText}>SENTINEL/IDS</div>
            <div className={styles.logoTag}>v2.4 · access request</div>
          </div>
        </div>

        <h2 className={styles.sidebarTitle}>
          Join the<br />operator team.
        </h2>
        <p className={styles.sidebarSub}>
          Three quick steps and you'll be reviewing live threat data
          alongside the rest of the SOC.
        </p>
      </div>

      {/* Onboarding pipeline */}
      <div className={styles.sidebarSteps}>
        {[
          { title: 'Fill in your details',   sub: 'Identity + role'   },
          { title: 'Wait for admin approval', sub: 'Usually < 24h'    },
          { title: 'Access the console',      sub: 'Start monitoring' },
        ].map((s, i) => (
          <div key={i} className={styles.step}>
            <div className={styles.stepNum}>
              <span>{String(i + 1).padStart(2, '0')}</span>
            </div>
            <div className={styles.stepBody}>
              <div className={styles.stepTitle}>{s.title}</div>
              <div className={styles.stepSub}>{s.sub}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <p className={styles.sidebarFooter}>
        <span className={styles.statusDot} aria-hidden="true" />
        Onboarding pipeline active
      </p>
    </>
  )
}

function Field({ label, name, value, onChange, error, placeholder, type = 'text', icon }) {
  return (
    <div className={styles.fieldWrap}>
      <label className={styles.label}>{label}</label>
      <div className={styles.inputWrap}>
        {icon && <span className={styles.inputIcon}>{icon}</span>}
        <input
          type={type}
          name={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={`${styles.input} ${icon ? styles.inputWithIcon : ''} ${error ? styles.inputError : ''}`}
        />
      </div>
      {error && <span className={styles.errorMsg}>{error}</span>}
    </div>
  )
}

const EmailIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
  </svg>
)
const LockIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
)
const EyeIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
  </svg>
)
const EyeOffIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
)