import { useState, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { adminService } from '../services/api.js'
import { useTheme } from '../context/ThemeContext.jsx'
import styles from './PendingUsersPage.module.css'
import '../styles/tokens.css'

const SPECIALTY_INFO = {
  ia_user:  { label: 'IA User',  color: 'var(--new)',    bg: 'color-mix(in srgb, var(--new) 10%, transparent)',    border: 'color-mix(in srgb, var(--new) 30%, transparent)' },
  soc_user: { label: 'SOC User', color: 'var(--accent)', bg: 'color-mix(in srgb, var(--accent) 10%, transparent)', border: 'color-mix(in srgb, var(--accent) 30%, transparent)' },
  admin:    { label: 'Admin',    color: 'var(--warn)',   bg: 'color-mix(in srgb, var(--warn) 10%, transparent)',   border: 'color-mix(in srgb, var(--warn) 30%, transparent)' },
}

export default function PendingUsersPage() {
  const { theme } = useTheme()
  const [users, setUsers]     = useState([])
  const [loading, setLoading] = useState(true)
  const [acting, setActing]   = useState(null)
  const [toast, setToast]     = useState(null)

  useEffect(() => { fetchUsers() }, [])

  async function fetchUsers() {
    setLoading(true)
    try {
      const data = await adminService.getPendingUsers()
      setUsers(data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  async function handleAction(email, action) {
    setActing(email)
    try {
      await adminService.approveUser(email, action)
      setUsers(u => u.filter(u => u.email !== email))
      showToast(action === 'approve' ? 'User approved and notified' : 'User rejected', action)
    } catch (e) {
      showToast('Something went wrong', 'error')
    } finally {
      setActing(null)
    }
  }

  function showToast(msg, type) {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  return (
    <div className={`${styles.layout} dash-theme`} data-theme={theme}>
      <Sidebar />
      <main className={styles.main}>
        <div className={styles.header}>
          <div>
            <h1 className={styles.title}>Pending Users</h1>
            <p className={styles.sub}>Review and approve or reject registration requests</p>
          </div>
          <span className={styles.countBadge}>{users.length} pending</span>
        </div>

        {toast && (
          <div className={`${styles.toast} ${styles['toast_' + toast.type]}`}>
            {toast.type === 'approve' ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
              </svg>
            )}
            {toast.msg}
          </div>
        )}

        {loading ? (
          <div className={styles.empty}>Loading…</div>
        ) : users.length === 0 ? (
          <div className={styles.empty}>
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{color:'var(--accent)', marginBottom:'1rem', opacity:0.6}}>
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <p>No pending requests</p>
            <span>All registrations have been reviewed.</span>
          </div>
        ) : (
          <div className={styles.table}>
            <div className={styles.tableHead}>
              <span>User</span>
              <span>Specialty</span>
              <span>Phone</span>
              <span>Sex</span>
              <span>Actions</span>
            </div>
            {users.map(u => {
              const sp = SPECIALTY_INFO[u.specialty]
              return (
                <div key={u.email} className={styles.tableRow}>
                  <div className={styles.userCell}>
                    <div className={styles.avatar}>
                      {(u.first_name?.[0] || u.email[0]).toUpperCase()}
                    </div>
                    <div>
                      <p className={styles.userName}>
                        {u.first_name || u.last_name
                          ? `${u.first_name} ${u.last_name}`.trim()
                          : '—'}
                      </p>
                      <p className={styles.userEmail}>{u.email}</p>
                    </div>
                  </div>
                  <span
                    className={styles.specialtyBadge}
                    style={sp ? { color: sp.color, background: sp.bg, borderColor: sp.border } : { color: 'var(--text-faint)', background: 'var(--surface-2)', borderColor: 'var(--border)' }}
                  >
                    <span className={styles.specialtyDot} style={{ background: sp?.color || 'var(--text-faint)' }} />
                    {sp?.label || u.specialty || '—'}
                  </span>
                  <span className={styles.cell}>{u.phone || '—'}</span>
                  <span className={styles.cell} style={{textTransform:'capitalize'}}>{u.sex || '—'}</span>
                  <div className={styles.actions}>
                    <button
                      className={styles.approveBtn}
                      disabled={acting === u.email}
                      onClick={() => handleAction(u.email, 'approve')}
                    >
                      {acting === u.email ? '…' : 'Approve'}
                    </button>
                    <button
                      className={styles.rejectBtn}
                      disabled={acting === u.email}
                      onClick={() => handleAction(u.email, 'reject')}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}