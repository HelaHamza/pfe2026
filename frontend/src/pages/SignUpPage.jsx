import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authService } from '../services/api.js'
import styles from './SignUpPage.module.css'

const SPECIALTIES = [
  { value: 'ia_user',  label: 'IA User' },
  { value: 'soc_user', label: 'SOC User' },
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

  if (success) return (
    <div className={styles.page}>
      <aside className={styles.sidebar}>
        <SidebarContent />
      </aside>
      <main className={styles.main}>
        <div className={styles.successCard}>
          <div className={styles.successIcon}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          </div>
          <h2 className={styles.successTitle}>Registration submitted!</h2>
          <p className={styles.successText}>
            Your account is pending admin approval. You'll receive an email once it's been reviewed.
          </p>
          <button className={styles.backBtn} onClick={() => navigate('/login')}>
            Back to login
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
            <p className={styles.cardSub}>Fill in your details to register</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <div className={styles.row}>
              <Field label="First Name" name="first_name" value={form.first_name} onChange={handleChange} error={errors.first_name} placeholder="Yassine" />
              <Field label="Last Name"  name="last_name"  value={form.last_name}  onChange={handleChange} error={errors.last_name}  placeholder="Benali" />
            </div>

            <Field label="Email" name="email" type="email" value={form.email} onChange={handleChange} error={errors.email} placeholder="you@example.com" icon={<EmailIcon />} />

            <div className={styles.fieldWrap}>
              <label className={styles.label}>Password</label>
              <div className={styles.inputWrap}>
                <span className={styles.inputIcon}><LockIcon /></span>
                <input
                  type={showPw ? 'text' : 'password'}
                  name="password"
                  value={form.password}
                  onChange={handleChange}
                  placeholder="Min. 6 characters"
                  className={`${styles.input} ${errors.password ? styles.inputError : ''}`}
                />
                <button type="button" className={styles.togglePw} onClick={() => setShowPw(v => !v)} aria-label="Toggle password">
                  {showPw ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
              {errors.password && <span className={styles.errorMsg}>{errors.password}</span>}
            </div>

            <div className={styles.row}>
              <Field label="Phone (optional)" name="phone" type="tel" value={form.phone} onChange={handleChange} placeholder="+213 xxx xxx xxx" />
              <div className={styles.fieldWrap}>
                <label className={styles.label}>Sex (optional)</label>
                <select name="sex" value={form.sex} onChange={handleChange} className={styles.select}>
                  <option value="">Select…</option>
                  <option value="male">Male</option>
                  <option value="female">Female</option>
                  <option value="other">Prefer not to say</option>
                </select>
              </div>
            </div>

            <div className={styles.fieldWrap}>
              <label className={styles.label}>Specialty</label>
              <div className={styles.specialtyGroup}>
                {SPECIALTIES.map(s => (
                  <label key={s.value} className={`${styles.specialtyOption} ${form.specialty === s.value ? styles.specialtyActive : ''}`}>
                    <input type="radio" name="specialty" value={s.value} checked={form.specialty === s.value} onChange={handleChange} hidden />
                    {s.label}
                  </label>
                ))}
              </div>
            </div>

            {error && (
              <div className={styles.alert}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                {error}
              </div>
            )}

            <button type="submit" className={styles.submitBtn} disabled={loading}>
              {loading && <span className={styles.spinner} />}
              {loading ? 'Registering…' : 'Create account'}
            </button>

            <p className={styles.loginLink}>
              Already have an account? <Link to="/login">Sign in</Link>
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
      <div>
        <div className={styles.logoRow}>
          <div className={styles.logoMark}>
            <svg width="16" height="16" viewBox="0 0 20 20" fill="none">
              <path d="M10 2L2 7v6l8 5 8-5V7L10 2Z" stroke="#1a1a2e" strokeWidth="1.6" strokeLinejoin="round"/>
              <path d="M2 7l8 5 8-5" stroke="#1a1a2e" strokeWidth="1.6"/>
              <path d="M10 12v5" stroke="#1a1a2e" strokeWidth="1.6"/>
            </svg>
          </div>
          <span className={styles.logoText}>PFE 2026</span>
        </div>
        <h2 className={styles.sidebarTitle}>Join the<br />platform</h2>
        <p className={styles.sidebarSub}>Academic Platform · PFE 2026</p>
      </div>
      <div className={styles.sidebarSteps}>
        {['Fill in your details', 'Wait for admin approval', 'Log in and get started'].map((s, i) => (
          <div key={i} className={styles.step}>
            <div className={styles.stepNum}>{i + 1}</div>
            <span>{s}</span>
          </div>
        ))}
      </div>
      <p className={styles.sidebarFooter}>© 2026 · PFE Project</p>
    </>
  )
}

function Field({ label, name, value, onChange, error, placeholder, type = 'text', icon }) {
  return (
    <div className={styles.fieldWrap}>
      <label className={styles.label}>{label}</label>
      <div className={styles.inputWrap}>
        {icon && <span className={styles.inputIcon}>{icon}</span>}
        <input type={type} name={name} value={value} onChange={onChange} placeholder={placeholder}
          className={`${styles.input} ${icon ? styles.inputWithIcon : ''} ${error ? styles.inputError : ''}`} />
      </div>
      {error && <span className={styles.errorMsg}>{error}</span>}
    </div>
  )
}

const EmailIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
  </svg>
)
const LockIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
)
const EyeIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
  </svg>
)
const EyeOffIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
)