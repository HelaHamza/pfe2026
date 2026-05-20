import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import styles from './Sidebar.module.css'

const NAV_USER = [
  { to: '/home',      label: 'Home',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg> },
  { to: '/profile',   label: 'Profile',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> },
  { to: '/dashboard', label: 'Dashboard',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg> },
  { to: '/logs',      label: 'Logs Analysed',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg> },
]

const NAV_ADMIN_TOP = [
  { to: '/home',    label: 'Home',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg> },
  { to: '/profile', label: 'Profile',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> },
]

const NAV_ADMIN = [
  { to: '/admin/pending',   label: 'Pending Users',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> },
  { to: '/admin/users',     label: 'Approved Users',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="23 11 17 17 14 14"/></svg> },
  { to: '/admin/feedbacks', label: 'Feedbacks',
    icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg> },
]

export default function Sidebar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const isAdmin  = user?.role === 'admin'
  const initials = user?.email?.[0]?.toUpperCase() ?? 'A'

  function handleLogout() { logout(); navigate('/login', { replace: true }) }

  return (
    <aside className={styles.sidebar}>
      <div className={styles.brand}>
        <div className={styles.logoMark}>
          <svg width="16" height="16" viewBox="0 0 20 20" fill="none">
            <path d="M10 2L2 7v6l8 5 8-5V7L10 2Z" stroke="#1a1a2e" strokeWidth="1.6" strokeLinejoin="round"/>
            <path d="M2 7l8 5 8-5" stroke="#1a1a2e" strokeWidth="1.6"/>
            <path d="M10 12v5" stroke="#1a1a2e" strokeWidth="1.6"/>
          </svg>
        </div>
        <span className={styles.brandName}>PFE 2026</span>
      </div>

      <nav className={styles.nav}>
        {(isAdmin ? NAV_ADMIN_TOP : NAV_USER).map(({ to, label, icon }) => (
          <NavLink key={to} to={to}
            className={({ isActive }) => `${styles.navItem} ${isActive ? styles.navItemActive : ''}`}>
            <span className={styles.navIcon}>{icon}</span>{label}
          </NavLink>
        ))}

        {isAdmin && (
          <>
            <p className={styles.navSection}>Admin</p>
            {NAV_ADMIN.map(({ to, label, icon }) => (
              <NavLink key={to} to={to}
                className={({ isActive }) => `${styles.navItem} ${isActive ? styles.navItemActive : ''}`}>
                <span className={styles.navIcon}>{icon}</span>{label}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      <div className={styles.bottom}>
        <div className={styles.userRow}>
          <div className={styles.avatar}>{initials}</div>
          <div className={styles.userInfo}>
            <span className={styles.userEmail}>{user?.email}</span>
            <span className={styles.userRole}>{user?.role}</span>
          </div>
        </div>
        <button className={styles.logoutBtn} onClick={handleLogout}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
          </svg>
          Log out
        </button>
      </div>
    </aside>
  )
}