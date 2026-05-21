import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { feedbackService } from '../services/api.js'
import styles from './HomePage.module.css'

const NAV_LINKS = ['About', 'Testimonials', 'Contact']

export default function HomePage() {
  const { user, logout } = useAuth()
  const navigate  = useNavigate()
  const isAdmin   = user?.role === 'admin'
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const [testimonials, setTestimonials] = useState([])
  const [feedback, setFeedback]         = useState('')
  const [rating, setRating]             = useState(0)
  const [hoverRating, setHoverRating]   = useState(0)
  const [fbStatus, setFbStatus]         = useState(null) // 'sent' | 'error'
  const [fbLoading, setFbLoading]       = useState(false)
  const dropdownRef = useRef(null)

  useEffect(() => {
    feedbackService.getApproved().then(setTestimonials).catch(() => {})
  }, [])

  useEffect(() => {
    function handleClick(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target))
        setDropdownOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  function handleLogout() { logout(); navigate('/login', { replace: true }) }

  async function handleFeedbackSubmit(e) {
    e.preventDefault()
    if (!feedback.trim()) return
    setFbLoading(true)
    try {
      await feedbackService.submit(feedback, rating || null)
      setFbStatus('sent')
      setFeedback('')
      setRating(0)
    } catch {
      setFbStatus('error')
    } finally {
      setFbLoading(false)
    }
  }

  const initials = user?.email?.[0]?.toUpperCase() ?? 'A'
  const navLinks = isAdmin ? ['About', 'Testimonials'] : NAV_LINKS

  return (
    <div className={styles.page}>

      {/* ── Navbar ── */}
      <header className={styles.navbar}>
        <div className={styles.navLogo}>
          <div className={styles.logoMark}>
            <svg width="16" height="16" viewBox="0 0 20 20" fill="none">
              <path d="M10 2L2 7v6l8 5 8-5V7L10 2Z" stroke="#1a1a2e" strokeWidth="1.6" strokeLinejoin="round"/>
              <path d="M2 7l8 5 8-5" stroke="#1a1a2e" strokeWidth="1.6"/>
              <path d="M10 12v5" stroke="#1a1a2e" strokeWidth="1.6"/>
            </svg>
          </div>
          <span className={styles.logoText}>PFE 2026</span>
        </div>

        <nav className={styles.navLinks}>
          {navLinks.map(link => (
            <a key={link} href={`#${link.toLowerCase()}`} className={styles.navLink}>{link}</a>
          ))}
        </nav>

        <div className={styles.navRight} ref={dropdownRef}>
          <button className={styles.avatarBtn} onClick={() => setDropdownOpen(v => !v)} aria-label="User menu">
            <div className={styles.avatar}>{initials}</div>
            <svg className={`${styles.chevron} ${dropdownOpen ? styles.chevronOpen : ''}`} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </button>

          {dropdownOpen && (
            <div className={styles.dropdown}>
              <div className={styles.dropdownHeader}>
                <span className={styles.dropdownEmail}>{user?.email}</span>
                <span className={styles.dropdownRole}>{user?.role}</span>
              </div>
              <div className={styles.dropdownDivider} />
              <button className={styles.dropdownItem} onClick={() => { navigate('/profile'); setDropdownOpen(false) }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                Profile
              </button>
              <button className={styles.dropdownItem} onClick={() => { navigate('/dashboard'); setDropdownOpen(false) }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                Dashboard
              </button>
              <div className={styles.dropdownDivider} />
              <button className={`${styles.dropdownItem} ${styles.dropdownLogout}`} onClick={handleLogout}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Log out
              </button>
            </div>
          )}
        </div>
      </header>

      {/* ── Hero ── */}
      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <p className={styles.heroEyebrow}>Academic Platform · PFE 2026</p>
          <h1 className={styles.heroTitle}>Analyse your data<br /><em>with precision</em></h1>
          <p className={styles.heroSub}>A powerful platform built for research, analysis, and academic excellence.</p>
          <button className={styles.analyseBtn} onClick={() => navigate('/analyse')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            Analyse
          </button>
        </div>
        <div className={styles.decor1} />
        <div className={styles.decor2} />
      </section>

      {/* ── About ── */}
      <section id="about" className={styles.section}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionTag}>About</span>
          <h2 className={styles.sectionTitle}>What is this platform?</h2>
          <p className={styles.sectionText}>
            This platform was built as part of a final-year academic project (PFE 2026).
            It provides administrators and researchers with tools to manage, analyse, and visualise data efficiently.
          </p>
        </div>
      </section>

      {/* ── Testimonials ── */}
      <section id="testimonials" className={`${styles.section} ${styles.sectionAlt}`}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionTag}>Testimonials</span>
          <h2 className={styles.sectionTitle}>What people say</h2>
          {testimonials.length === 0 ? (
            <p className={styles.sectionText} style={{fontStyle:'italic',color:'#aaa'}}>No testimonials yet. Be the first to share your feedback!</p>
          ) : (
            <div className={styles.testimonialGrid}>
              {testimonials.map(t => (
                <div key={t.id} className={styles.testimonialCard}>
                  {t.rating && (
                    <div className={styles.stars}>
                      {[1,2,3,4,5].map(s => (
                        <span key={s} style={{color: s <= t.rating ? '#c9a96e' : '#ddd'}}>★</span>
                      ))}
                    </div>
                  )}
                  <p className={styles.testimonialText}>"{t.message}"</p>
                  <div className={styles.testimonialAuthor}>
                    <div className={styles.testimonialAvatar}>{t.user_name[0]}</div>
                    <div>
                      <p className={styles.testimonialName}>{t.user_name}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* ── Contact — non-admin only ── */}
      {!isAdmin && (
        <section id="contact" className={styles.section}>
          <div className={styles.contactGrid}>

            {/* Left — info panel */}
            <div className={styles.contactInfo}>
              <span className={styles.sectionTag}>Contact</span>
              <h2 className={styles.sectionTitle}>Share your experience</h2>
              <p className={styles.sectionText}>
                Your feedback helps us improve the platform and inspires other users.
                Approved testimonials appear in the Testimonials section above.
              </p>

              <div className={styles.contactSteps}>
                {[
                  { label: 'Write your feedback', desc: 'Share your honest experience with the platform in a few words.' },
                  { label: 'Admin reviews it', desc: 'Our team reads every submission carefully before publishing.' },
                  { label: 'Get published', desc: 'Once approved, your testimonial goes live for everyone to see.' },
                ].map((s, i) => (
                  <div key={i} className={styles.contactStep}>
                    <div className={styles.contactStepNum}>{i + 1}</div>
                    <div>
                      <p className={styles.contactStepLabel}>{s.label}</p>
                      <p className={styles.contactStepDesc}>{s.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right — form */}
            <div className={styles.contactFormWrap}>
              {fbStatus === 'sent' ? (
                <div className={styles.fbSuccess}>
                  <div className={styles.fbSuccessIcon}>
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  </div>
                  <h3 className={styles.fbSuccessTitle}>Feedback submitted!</h3>
                  <p className={styles.fbSuccessText}>Thank you for sharing your thoughts. You'll receive an email once your feedback has been reviewed by our team.</p>
                  <button className={styles.fbSuccessBtn} onClick={() => setFbStatus(null)}>Submit another</button>
                </div>
              ) : (
                <form onSubmit={handleFeedbackSubmit} className={styles.fbForm} noValidate>
                  <p className={styles.fbFormTitle}>Leave a testimonial</p>

                  {/* Star rating */}
                  <div className={styles.ratingWrap}>
                    <label className={styles.fbLabel}>Rate your experience</label>
                    <div className={styles.starRow}>
                      {[1,2,3,4,5].map(s => (
                        <button key={s} type="button"
                          className={`${styles.starBtn} ${s <= (hoverRating || rating) ? styles.starActive : ''}`}
                          onMouseEnter={() => setHoverRating(s)}
                          onMouseLeave={() => setHoverRating(0)}
                          onClick={() => setRating(r => r === s ? 0 : s)}
                          aria-label={`Rate ${s} star${s > 1 ? 's' : ''}`}
                        >★</button>
                      ))}
                      {(hoverRating || rating) > 0 && (
                        <span className={styles.ratingLabel}>
                          {['', 'Poor', 'Fair', 'Good', 'Very good', 'Excellent'][hoverRating || rating]}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Textarea */}
                  <div className={styles.fbField}>
                    <div className={styles.fbFieldHeader}>
                      <label className={styles.fbLabel}>Your message</label>
                      <span className={`${styles.charCount} ${feedback.length > 450 ? styles.charCountWarn : ''}`}>
                        {feedback.length}/500
                      </span>
                    </div>
                    <div className={styles.fbTextareaWrap}>
                      <textarea
                        className={styles.fbTextarea}
                        rows={5}
                        maxLength={500}
                        placeholder="Share your experience — what you found valuable, what could be improved…"
                        value={feedback}
                        onChange={e => { setFeedback(e.target.value); setFbStatus(null) }}
                        required
                      />
                      <div className={styles.fbFocusRing} />
                    </div>
                  </div>

                  {fbStatus === 'error' && (
                    <div className={styles.fbError}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                      Something went wrong. Please try again.
                    </div>
                  )}

                  <div className={styles.fbSubmitRow}>
                    <p className={styles.fbPrivacyNote}>Your name will appear with your testimonial if published.</p>
                    <button type="submit" className={styles.fbBtn} disabled={fbLoading || !feedback.trim()}>
                      {fbLoading
                        ? <><span className={styles.fbSpinner} />Sending…</>
                        : <>
                            Submit
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                          </>
                      }
                    </button>
                  </div>
                </form>
              )}
            </div>

          </div>
        </section>
      )}

            <footer className={styles.footer}>
        <p>© 2026 PFE Project · All rights reserved</p>
      </footer>
    </div>
  )
}