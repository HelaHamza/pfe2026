import { useState, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { adminService } from '../services/api.js'
import styles from './UsersPage.module.css'

const SPECIALTY_LABEL = { ia_user: 'IA User', soc_user: 'SOC User', admin: 'Admin' }

export default function PendingUsersPage() {
  const [users, setUsers]     = useState([])
  const [loading, setLoading] = useState(true)
  const [acting, setActing]   = useState(null)   // email currently being processed
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
      showToast(action === 'approve' ? '✓ User approved and notified' : '✗ User rejected', action)
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
    <div className={styles.layout}>
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
            {toast.msg}
          </div>
        )}

        {loading ? (
          <div className={styles.empty}>Loading…</div>
        ) : users.length === 0 ? (
          <div className={styles.empty}>
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{color:'#ccc',marginBottom:'1rem'}}>
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
            {users.map(u => (
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
                <span className={styles.specialtyBadge}>
                  {SPECIALTY_LABEL[u.specialty] || u.specialty || '—'}
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
            ))}
          </div>
        )}
      </main>
    </div>
  )
}