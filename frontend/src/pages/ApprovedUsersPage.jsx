import { useState, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { adminService } from '../services/api.js'
import { useTheme } from '../context/ThemeContext.jsx'
import styles from './UsersPage.module.css'
import '../styles/tokens.css'

const SPECIALTY_INFO = {
  ia_user:  { label: 'IA User',  color: 'var(--new)',    bg: 'color-mix(in srgb, var(--new) 10%, transparent)',    border: 'color-mix(in srgb, var(--new) 30%, transparent)' },
  soc_user: { label: 'SOC User', color: 'var(--accent)', bg: 'color-mix(in srgb, var(--accent) 10%, transparent)', border: 'color-mix(in srgb, var(--accent) 30%, transparent)' },
  admin:    { label: 'Admin',    color: 'var(--warn)',   bg: 'color-mix(in srgb, var(--warn) 10%, transparent)',   border: 'color-mix(in srgb, var(--warn) 30%, transparent)' },
}

export default function ApprovedUsersPage() {
  const { theme } = useTheme()
  const [users, setUsers]     = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch]   = useState('')

  useEffect(() => {
    adminService.getAllUsers()
      .then(data => setUsers(data.filter(u => u.status === 'approved')))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const filtered = users.filter(u =>
    `${u.first_name} ${u.last_name} ${u.email}`.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className={`${styles.layout} dash-theme`} data-theme={theme}>
      <Sidebar />
      <main className={styles.main}>
        <div className={styles.header}>
          <div>
            <h1 className={styles.title}>Approved Users</h1>
            <p className={styles.sub}>All active accounts on the platform</p>
          </div>
          <span className={styles.countBadge}>{users.length} users</span>
        </div>

        <div className={styles.searchWrap}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            className={styles.searchInput}
            placeholder="Search by name or email…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {loading ? (
          <div className={styles.empty}>Loading…</div>
        ) : filtered.length === 0 ? (
          <div className={styles.empty}>
            <p>{search ? 'No users match your search.' : 'No approved users yet.'}</p>
          </div>
        ) : (
          <div className={styles.table}>
            <div className={styles.tableHead}>
              <span>User</span>
              <span>Specialty</span>
              <span>Phone</span>
              <span>Sex</span>
              <span>Address</span>
            </div>
            {filtered.map(u => {
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
                  <span className={styles.cell}>{u.address || '—'}</span>
                </div>
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}