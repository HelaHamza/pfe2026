import { useState, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { feedbackService } from '../services/api.js'
import styles from './FeedbacksPage.module.css'

const STATUS_COLORS = {
  pending:  { bg: 'rgba(251,191,36,0.1)',  color: '#fbbf24', border: 'rgba(251,191,36,0.3)' },
  approved: { bg: 'rgba(74,222,128,0.1)',  color: '#4ade80', border: 'rgba(74,222,128,0.3)' },
  rejected: { bg: 'rgba(248,113,113,0.1)', color: '#f87171', border: 'rgba(248,113,113,0.3)' },
}

export default function FeedbacksPage() {
  const [feedbacks, setFeedbacks] = useState([])
  const [loading, setLoading]     = useState(true)
  const [filter, setFilter]       = useState('all')
  const [acting, setActing]       = useState(null)
  const [toast, setToast]         = useState(null)

  useEffect(() => { fetchFeedbacks() }, [])

  async function fetchFeedbacks() {
    setLoading(true)
    try { setFeedbacks(await feedbackService.getAll()) }
    catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  async function handleAction(id, action) {
    setActing(id)
    try {
      await feedbackService.action(id, action)
      setFeedbacks(f => f.map(fb => fb.id === id ? { ...fb, status: action === 'approve' ? 'approved' : 'rejected' } : fb))
      showToast(action === 'approve' ? 'Feedback approved and published' : 'Feedback rejected', action)
    } catch { showToast('Something went wrong', 'error') }
    finally { setActing(null) }
  }

  function showToast(msg, type) {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  const filtered = feedbacks.filter(f => filter === 'all' || f.status === filter)
  const counts = {
    all:      feedbacks.length,
    pending:  feedbacks.filter(f => f.status === 'pending').length,
    approved: feedbacks.filter(f => f.status === 'approved').length,
    rejected: feedbacks.filter(f => f.status === 'rejected').length,
  }

  return (
    <div className={styles.layout}>
      <Sidebar />
      <main className={styles.main}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.breadcrumb}>
            <span className={styles.dotGreen} />
            <span>Operator console</span>
            <span className={styles.crumbSep}>/</span>
            <span className={styles.crumbActive}>Feedbacks</span>
          </div>
          <h1 className={styles.title}>Feedbacks</h1>
          <p className={styles.sub}>Review and moderate user testimonials before publication.</p>
        </div>

        {/* Stats summary */}
        <div className={styles.statsGrid}>
          <StatCard label="Total"    value={counts.all}      tone="neutral" />
          <StatCard label="Pending"  value={counts.pending}  tone="warning" pulse={counts.pending > 0} />
          <StatCard label="Approved" value={counts.approved} tone="success" />
          <StatCard label="Rejected" value={counts.rejected} tone="danger"  />
        </div>

        {/* Filter tabs */}
        <div className={styles.tabs}>
          {['all', 'pending', 'approved', 'rejected'].map(t => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={`${styles.tab} ${filter === t ? styles.tabActive : ''}`}
            >
              <span>{t.charAt(0).toUpperCase() + t.slice(1)}</span>
              <span className={styles.tabCount}>{counts[t]}</span>
            </button>
          ))}
        </div>

        {toast && (
          <div className={`${styles.toast} ${styles['toast_' + (toast.type === 'approve' ? 'approve' : 'reject')]}`}>
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
          <div className={styles.loadingState}>
            <span className={styles.spinner} />
            <p className={styles.sub}>Loading feedbacks…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className={styles.emptyState}>
            <div className={styles.emptyIcon}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
              </svg>
            </div>
            <p className={styles.emptyTitle}>No {filter === 'all' ? '' : filter} feedbacks yet</p>
            <p className={styles.emptyText}>
              {filter === 'pending'
                ? 'You\'re all caught up — no items need review.'
                : 'New submissions will appear here once received.'}
            </p>
          </div>
        ) : (
          <div className={styles.cards}>
            {filtered.map(fb => {
              const sc = STATUS_COLORS[fb.status]
              return (
                <div key={fb.id} className={styles.card}>
                  <div className={styles.cardTop}>
                    <div className={styles.userRow}>
                      <div className={styles.avatar}>{fb.user_name[0]?.toUpperCase()}</div>
                      <div className={styles.userMeta}>
                        <p className={styles.userName}>{fb.user_name}</p>
                        <p className={styles.userEmail}>{fb.user_email}</p>
                      </div>
                    </div>
                    <span
                      className={styles.statusBadge}
                      style={{ background: sc.bg, color: sc.color, borderColor: sc.border }}
                    >
                      <span className={styles.statusDot} style={{ background: sc.color }} />
                      {fb.status}
                    </span>
                  </div>

                  {fb.rating && (
                    <div className={styles.stars}>
                      {[1,2,3,4,5].map(s => (
                        <svg
                          key={s}
                          width="14"
                          height="14"
                          viewBox="0 0 24 24"
                          fill={s <= fb.rating ? '#4ade80' : 'none'}
                          stroke={s <= fb.rating ? '#4ade80' : '#3a4055'}
                          strokeWidth="1.8"
                          strokeLinejoin="round"
                        >
                          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                        </svg>
                      ))}
                      <span className={styles.ratingNum}>{fb.rating}/5</span>
                    </div>
                  )}

                  <p className={styles.message}>"{fb.message}"</p>

                  <div className={styles.cardFooter}>
                    <p className={styles.date}>
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{verticalAlign:'-1px', marginRight:'4px'}}>
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>
                      </svg>
                      {new Date(fb.created_at).toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' })}
                    </p>

                    {fb.status === 'pending' && (
                      <div className={styles.actions}>
                        <button
                          className={styles.rejectBtn}
                          disabled={acting === fb.id}
                          onClick={() => handleAction(fb.id, 'reject')}
                        >
                          Reject
                        </button>
                        <button
                          className={styles.approveBtn}
                          disabled={acting === fb.id}
                          onClick={() => handleAction(fb.id, 'approve')}
                        >
                          {acting === fb.id ? (
                            <span className={styles.btnSpinner} />
                          ) : (
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                              <polyline points="20 6 9 17 4 12"/>
                            </svg>
                          )}
                          <span>{acting === fb.id ? 'Working…' : 'Approve'}</span>
                        </button>
                      </div>
                    )}
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

function StatCard({ label, value, tone, pulse }) {
  return (
    <div className={`${styles.statCard} ${styles['stat_' + tone]}`}>
      <div className={styles.statLabelRow}>
        <span className={styles.statLabel}>{label}</span>
        {pulse && <span className={styles.statPulse} />}
      </div>
      <p className={styles.statValue}>{value}</p>
    </div>
  )
}