import { useState, useEffect } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import { feedbackService } from '../services/api.js'
import styles from './FeedbacksPage.module.css'

const STATUS_COLORS = {
  pending:  { bg: '#fff8ec', color: '#b8760a', border: 'rgba(184,118,10,0.2)' },
  approved: { bg: '#edf7f2', color: '#1a6b45', border: 'rgba(26,107,69,0.15)' },
  rejected: { bg: '#fdf0ef', color: '#c0392b', border: 'rgba(192,57,43,0.15)' },
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
      showToast(action === 'approve' ? '✓ Feedback approved and published' : '✗ Feedback rejected', action)
    } catch { showToast('Something went wrong', 'error') }
    finally { setActing(null) }
  }

  function showToast(msg, type) {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  const filtered = feedbacks.filter(f => filter === 'all' || f.status === filter)
  const counts = { all: feedbacks.length, pending: feedbacks.filter(f => f.status === 'pending').length, approved: feedbacks.filter(f => f.status === 'approved').length, rejected: feedbacks.filter(f => f.status === 'rejected').length }

  return (
    <div className={styles.layout}>
      <Sidebar />
      <main className={styles.main}>
        <div className={styles.header}>
          <div>
            <h1 className={styles.title}>Feedbacks</h1>
            <p className={styles.sub}>Review and manage user testimonials</p>
          </div>
        </div>

        {/* Filter tabs */}
        <div className={styles.tabs}>
          {['all', 'pending', 'approved', 'rejected'].map(t => (
            <button key={t} onClick={() => setFilter(t)}
              className={`${styles.tab} ${filter === t ? styles.tabActive : ''}`}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
              <span className={styles.tabCount}>{counts[t]}</span>
            </button>
          ))}
        </div>

        {toast && (
          <div className={`${styles.toast} ${styles['toast_' + (toast.type === 'approve' ? 'approve' : 'reject')]}`}>
            {toast.msg}
          </div>
        )}

        {loading ? (
          <p className={styles.empty}>Loading…</p>
        ) : filtered.length === 0 ? (
          <div className={styles.emptyState}>
            <p>No {filter === 'all' ? '' : filter} feedbacks yet.</p>
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
                      <div>
                        <p className={styles.userName}>{fb.user_name}</p>
                        <p className={styles.userEmail}>{fb.user_email}</p>
                      </div>
                    </div>
                    <span className={styles.statusBadge} style={{background: sc.bg, color: sc.color, border: `1px solid ${sc.border}`}}>
                      {fb.status}
                    </span>
                  </div>

                  {fb.rating && (
                    <div className={styles.stars}>
                      {[1,2,3,4,5].map(s => (
                        <span key={s} style={{color: s <= fb.rating ? '#c9a96e' : '#ddd'}}>★</span>
                      ))}
                    </div>
                  )}

                  <p className={styles.message}>"{fb.message}"</p>
                  <p className={styles.date}>{new Date(fb.created_at).toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' })}</p>

                  {fb.status === 'pending' && (
                    <div className={styles.actions}>
                      <button className={styles.approveBtn} disabled={acting === fb.id} onClick={() => handleAction(fb.id, 'approve')}>
                        {acting === fb.id ? '…' : 'Approve & Publish'}
                      </button>
                      <button className={styles.rejectBtn} disabled={acting === fb.id} onClick={() => handleAction(fb.id, 'reject')}>
                        Reject
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}