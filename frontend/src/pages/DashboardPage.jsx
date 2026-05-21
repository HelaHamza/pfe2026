import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import styles from './DashboardPage.module.css'

export default function DashboardPage() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className={styles.page}>
      {/* ── Topbar ── */}
      <header className={styles.topbar}>
        <div className={styles.brand}>
          <div className={styles.logoMark}>
            <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
              <path d="M10 2L2 7v6l8 5 8-5V7L10 2Z" stroke="#1a1a2e" strokeWidth="1.5" strokeLinejoin="round"/>
              <path d="M2 7l8 5 8-5" stroke="#1a1a2e" strokeWidth="1.5"/>
              <path d="M10 12v5" stroke="#1a1a2e" strokeWidth="1.5"/>
            </svg>
          </div>
          <span className={styles.brandName}>PFE 2026</span>
        </div>

        <div className={styles.topbarRight}>
          <div className={styles.userBadge}>
            <div className={styles.avatar}>
              {user?.email?.[0]?.toUpperCase() ?? 'A'}
            </div>
            <div className={styles.userInfo}>
              <span className={styles.userEmail}>{user?.email}</span>
              <span className={styles.userRole}>{user?.role}</span>
            </div>
          </div>
          <button className={styles.logoutBtn} onClick={handleLogout}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
            Logout
          </button>
        </div>
      </header>

      {/* ── Content ── */}
      <main className={styles.main}>
        <div className={styles.welcome}>
          <h1 className={styles.welcomeTitle}>Dashboard</h1>
          <p className={styles.welcomeSub}>Welcome back, <strong>{user?.email}</strong></p>
        </div>

        {/* Stat cards */}
        <div className={styles.statsGrid}>
          {[
            { label: 'Total Users',    value: '—', icon: 'users' },
            { label: 'Active Sessions', value: '—', icon: 'activity' },
            { label: 'Your Role',       value: user?.role ?? '—', icon: 'shield' },
          ].map((s) => (
            <div key={s.label} className={styles.statCard}>
              <p className={styles.statLabel}>{s.label}</p>
              <p className={styles.statValue}>{s.value}</p>
            </div>
          ))}
        </div>

        <div className={styles.placeholder}>
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>
            <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
          </svg>
          <p>Your modules will appear here.</p>
          <span>Start building your platform features.</span>
        </div>
      </main>
    </div>
  )
}