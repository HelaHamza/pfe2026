import { useState, useRef, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { profileService } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import styles from './ProfilePage.module.css'

// Icônes de champ — même style que Login (stroke 2), pour l'homogénéité des formulaires
const IconUser = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
  </svg>
)
const IconPhone = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z" />
  </svg>
)
const IconPin = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" /><circle cx="12" cy="10" r="3" />
  </svg>
)
const IconMail = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2" /><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </svg>
)

export default function ProfilePage() {
  const { user } = useAuth()
  const [form, setForm]       = useState({ first_name: '', last_name: '', phone: '', sex: '', address: '' })
  const [avatar, setAvatar]   = useState(null)
  const [saved, setSaved]     = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [errors, setErrors]   = useState({})
  const fileRef = useRef(null)

  useEffect(() => {
    profileService.getMe()
      .then((data) => {
        setForm({
          first_name: data.first_name || '',
          last_name:  data.last_name  || '',
          phone:      data.phone      || '',
          sex:        data.sex        || '',
          address:    data.address    || '',
        })
        if (data.avatar) setAvatar(data.avatar)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  function handleChange(e) {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }))
    setErrors(er => ({ ...er, [e.target.name]: '' }))
    setSaved(false)
  }

  function handleAvatar(e) {
    const file = e.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setAvatar(reader.result)
    reader.readAsDataURL(file)
    setSaved(false)
  }

  function validate() {
    const err = {}
    if (form.phone && !/^\+?[\d\s\-()]{6,}$/.test(form.phone))
      err.phone = 'Invalid phone number'
    return err
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const err = validate()
    if (Object.keys(err).length) { setErrors(err); return }

    const payload = {}
    Object.entries(form).forEach(([k, v]) => { if (v !== '') payload[k] = v })
    if (avatar) payload.avatar = avatar

    setSaving(true)
    try {
      await profileService.updateMe(payload)
      setSaved(true)
    } catch (err) {
      console.error(err)
    } finally {
      setSaving(false)
    }
  }

  const initials = (() => {
    const f = form.first_name?.[0] || ''
    const l = form.last_name?.[0]  || ''
    return (f + l).toUpperCase() || (user?.email?.[0] || '?').toUpperCase()
  })()

  const roleLabel = user?.specialty === 'soc_user' ? 'SOC Operator'
                  : user?.specialty === 'ia_user'  ? 'IA Analyst'
                  : 'Operator'

  if (loading) return (
    <div className={styles.layout}>
      <Sidebar />
      <main className={styles.main}>
        <div className={styles.loadingState}>
          <span className={styles.spinner} />
          <p className={styles.sub}>Loading profile…</p>
        </div>
      </main>
    </div>
  )

  return (
    <div className={styles.layout}>
      <Sidebar />
      <main className={styles.main}>
        <div className={styles.header}>
          <div className={styles.breadcrumb}>
            <span className={styles.dotGreen} />
            <span>Operator console</span>
            <span className={styles.crumbSep}>/</span>
            <span className={styles.crumbActive}>Profile</span>
          </div>
          <h1 className={styles.title}>Profile</h1>
          <p className={styles.sub}>Manage your operator identity and contact details.</p>
        </div>

        <form onSubmit={handleSubmit} noValidate className={styles.form}>

          {/* ─── Avatar / Identity card ─── */}
          <div className={styles.avatarSection}>
            <div
              className={styles.avatarWrap}
              role="button"
              tabIndex={0}
              aria-label="Change profile photo"
              onClick={() => fileRef.current.click()}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileRef.current.click() } }}
            >
              {avatar
                ? <img src={avatar} alt="Profile" className={styles.avatarImg} />
                : <div className={styles.avatarPlaceholder}>
                    <span className={styles.avatarInitials}>{initials}</span>
                  </div>
              }
              <div className={styles.avatarOverlay}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>
                </svg>
              </div>
            </div>
            <input ref={fileRef} type="file" accept="image/*" hidden onChange={handleAvatar} />
            <div className={styles.avatarMeta}>
              <p className={styles.avatarName}>
                {form.first_name || form.last_name
                  ? `${form.first_name} ${form.last_name}`.trim()
                  : user?.email}
              </p>
              <div className={styles.avatarBadges}>
                <span className={styles.roleBadge}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  {roleLabel}
                </span>
                <button type="button" className={styles.avatarChangeBtn} onClick={() => fileRef.current.click()}>
                  Change photo →
                </button>
              </div>
            </div>
          </div>

          {/* ─── Personal Information card ─── */}
          <div className={styles.card}>
            <div className={styles.cardHead}>
              <h2 className={styles.cardTitle}>
                <span className={styles.cardTitleDot} />
                Personal information
              </h2>
              <span className={styles.cardHint}>All fields optional</span>
            </div>

            {/* Email — read only */}
            <div className={styles.fieldWrap}>
              <label htmlFor="email" className={styles.label}>
                <span>Email</span>
                <span className={styles.labelHint}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" style={{verticalAlign:'-1px', marginRight:'3px'}}>
                    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                  </svg>
                  read-only
                </span>
              </label>
              <div className={styles.inputWrap}>
                <span className={styles.inputIcon}>{IconMail}</span>
                <input
                  id="email"
                  type="email"
                  value={user?.email || ''}
                  readOnly
                  className={`${styles.input} ${styles.inputReadonly}`}
                />
              </div>
            </div>

            <div className={styles.row}>
              <Field label="First name" name="first_name" value={form.first_name} onChange={handleChange} placeholder="Yassine" icon={IconUser} />
              <Field label="Last name"  name="last_name"  value={form.last_name}  onChange={handleChange} placeholder="Benali"  icon={IconUser} />
            </div>

            <div className={styles.row}>
              <Field label="Phone" name="phone" value={form.phone} onChange={handleChange} error={errors.phone} placeholder="+216 xx xxx xxx" type="tel" icon={IconPhone} />
              <div className={styles.fieldWrap}>
                <label htmlFor="sex" className={styles.label}>
                  <span>Sex</span>
                </label>
                <select id="sex" name="sex" value={form.sex} onChange={handleChange} className={styles.select}>
                  <option value="">Select…</option>
                  <option value="male">Male</option>
                  <option value="female">Female</option>
                  <option value="other">Prefer not to say</option>
                </select>
              </div>
            </div>

            <Field label="Address" name="address" value={form.address} onChange={handleChange} placeholder="Street, city, country" icon={IconPin} fullWidth />
          </div>

          {/* ─── Actions bar ─── */}
          <div className={styles.actions}>
            {saved && (
              <span className={styles.savedBadge}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                Changes saved
              </span>
            )}
            <button type="submit" className={styles.saveBtn} disabled={saving}>
              {saving && <span className={styles.btnSpinner} />}
              {saving ? 'Saving…' : 'Save changes'}
            </button>
          </div>

        </form>
      </main>
    </div>
  )
}

function Field({ label, name, value, onChange, error, placeholder, type = 'text', fullWidth, icon }) {
  return (
    <div className={`${styles.fieldWrap} ${fullWidth ? styles.fieldFull : ''}`}>
      <label htmlFor={name} className={styles.label}>
        <span>{label}</span>
      </label>
      <div className={styles.inputWrap}>
        {icon && <span className={styles.inputIcon}>{icon}</span>}
        <input
          id={name}
          type={type}
          name={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={`${styles.input} ${error ? styles.inputError : ''}`}
        />
      </div>
      {error && <span className={styles.errorMsg}>{error}</span>}
    </div>
  )
}