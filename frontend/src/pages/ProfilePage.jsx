import { useState, useRef, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { profileService } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import styles from './ProfilePage.module.css'

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

    // Only send fields that are filled
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

  if (loading) return (
    <div className={styles.layout}>
      <Sidebar />
      <main className={styles.main}><p className={styles.sub} style={{marginTop:'2rem'}}>Loading…</p></main>
    </div>
  )

  return (
    <div className={styles.layout}>
      <Sidebar />
      <main className={styles.main}>
        <div className={styles.header}>
          <h1 className={styles.title}>Profile</h1>
          <p className={styles.sub}>Manage your personal information</p>
        </div>

        <form onSubmit={handleSubmit} noValidate className={styles.form}>

          {/* Avatar */}
          <div className={styles.avatarSection}>
            <div className={styles.avatarWrap} onClick={() => fileRef.current.click()}>
              {avatar
                ? <img src={avatar} alt="Profile" className={styles.avatarImg} />
                : <div className={styles.avatarPlaceholder}>
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                    </svg>
                  </div>
              }
              <div className={styles.avatarOverlay}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>
                </svg>
              </div>
            </div>
            <input ref={fileRef} type="file" accept="image/*" hidden onChange={handleAvatar} />
            <div>
              <p className={styles.avatarName}>
                {form.first_name || form.last_name
                  ? `${form.first_name} ${form.last_name}`.trim()
                  : user?.email}
              </p>
              <button type="button" className={styles.avatarChangeBtn} onClick={() => fileRef.current.click()}>
                Change photo
              </button>
            </div>
          </div>

          {/* Fields */}
          <div className={styles.card}>
            <h2 className={styles.cardTitle}>Personal Information</h2>

            {/* Email — read only */}
            <div className={styles.fieldWrap}>
              <label className={styles.label}>Email</label>
              <input
                type="email"
                value={user?.email || ''}
                readOnly
                className={`${styles.input} ${styles.inputReadonly}`}
              />
            </div>

            <div className={styles.row}>
              <Field label="First Name (optional)" name="first_name" value={form.first_name} onChange={handleChange} placeholder="Yassine" />
              <Field label="Last Name (optional)"  name="last_name"  value={form.last_name}  onChange={handleChange} placeholder="Benali" />
            </div>

            <div className={styles.row}>
              <Field label="Phone (optional)" name="phone" value={form.phone} onChange={handleChange} error={errors.phone} placeholder="+213 xxx xxx xxx" type="tel" />
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

            <Field label="Address (optional)" name="address" value={form.address} onChange={handleChange} placeholder="Street, City, Country" fullWidth />
          </div>

          {/* Actions */}
          <div className={styles.actions}>
            {saved && (
              <span className={styles.savedBadge}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Saved successfully
              </span>
            )}
            <button type="submit" className={styles.saveBtn} disabled={saving}>
              {saving ? 'Saving…' : 'Save changes'}
            </button>
          </div>

        </form>
      </main>
    </div>
  )
}

function Field({ label, name, value, onChange, error, placeholder, type = 'text', fullWidth }) {
  return (
    <div className={`${styles.fieldWrap} ${fullWidth ? styles.fieldFull : ''}`}>
      <label className={styles.label}>{label}</label>
      <input type={type} name={name} value={value} onChange={onChange} placeholder={placeholder}
        className={`${styles.input} ${error ? styles.inputError : ''}`} />
      {error && <span className={styles.errorMsg}>{error}</span>}
    </div>
  )
}