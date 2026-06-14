import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { feedbackService } from '../services/api.js'
import styles from './Homepage.module.css'

const NAV_LINKS = ['About', 'Testimonials', 'Contact']

export default function HomePage() {
  const { user, logout } = useAuth()
  const navigate  = useNavigate()
  const isAdmin   = user?.role === 'admin'
  const specialty = user?.specialty

  const ia_user  = specialty === 'ia_user'
  const soc_user = specialty === 'soc_user'

  const [dropdownOpen, setDropdownOpen] = useState(false)
  const [testimonials, setTestimonials] = useState([])
  const [feedback, setFeedback]         = useState('')
  const [rating, setRating]             = useState(0)
  const [hoverRating, setHoverRating]   = useState(0)
  const [fbStatus, setFbStatus]         = useState(null)
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

  // Pretty role label for dropdown
  const roleLabel = isAdmin ? 'Administrator'
                   : soc_user ? 'SOC Operator'
                   : ia_user  ? 'IA Analyst'
                   : (user?.role || 'Operator')

  return (
    <div className={styles.page}>

      {/* ═══════════ Navbar ═══════════ */}
      <header className={styles.navbar}>
        <div className={styles.navLogo}>
          <div className={styles.logoMark}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#052e16" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div className={styles.logoTextWrap}>
            <span className={styles.logoText}>SENTINEL/IDS</span>
            <span className={styles.logoTag}>v2.4</span>
          </div>
        </div>

        <nav className={styles.navLinks}>
          {navLinks.map(link => (
            <a key={link} href={`#${link.toLowerCase()}`} className={styles.navLink}>{link}</a>
          ))}
        </nav>

        <div className={styles.navRight} ref={dropdownRef}>
          <button className={styles.avatarBtn} onClick={() => setDropdownOpen(v => !v)} aria-label="User menu">
            <div className={styles.avatar}>{initials}</div>
            <span className={styles.statusPing} aria-hidden="true" />
            <svg className={`${styles.chevron} ${dropdownOpen ? styles.chevronOpen : ''}`} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </button>

          {dropdownOpen && (
            <div className={styles.dropdown}>
              <div className={styles.dropdownHeader}>
                <span className={styles.dropdownEmail}>{user?.email}</span>
                <span className={styles.dropdownRole}>
                  <span className={styles.roleDot} />
                  {roleLabel}
                </span>
              </div>
              <div className={styles.dropdownDivider} />
              <button className={styles.dropdownItem} onClick={() => { navigate('/profile'); setDropdownOpen(false) }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                Profile
              </button>

              {isAdmin && (
                <button className={styles.dropdownItem} onClick={() => { navigate('/admin/pending'); setDropdownOpen(false) }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>
                  Admin dashboard
                </button>
              )}

              {ia_user && (
                <button className={styles.dropdownItem} onClick={() => { navigate('/ai-dashboard'); setDropdownOpen(false) }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z"/></svg>
                  AI Dashboard
                </button>
              )}

              {soc_user && (
                <button className={styles.dropdownItem} onClick={() => { navigate('/dashboard'); setDropdownOpen(false) }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>
                  SOC Dashboard
                </button>
              )}

              <div className={styles.dropdownDivider} />
              <button className={`${styles.dropdownItem} ${styles.dropdownLogout}`} onClick={handleLogout}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Log out
              </button>
            </div>
          )}
        </div>
      </header>

      {/* ═══════════ Hero ═══════════ */}
      <section className={styles.hero}>
        <div className={styles.heroGrid} aria-hidden="true" />
        <div className={styles.heroGlow} aria-hidden="true" />

        <div className={styles.heroInner}>
          <div className={styles.heroEyebrow}>
            <span className={styles.heroEyebrowDot} />
            <span>Linux threat detection · PFE 2026</span>
          </div>
          <h1 className={styles.heroTitle}>
            Detect, explain, and<br />
            investigate <em>Linux-targeted</em> attacks<br />
            in real time.
          </h1>
          <p className={styles.heroSub}>
            A unified console that pairs unsupervised ML anomaly detection with
            Sigma rule correlation — surfacing both known and unknown threats
            across your Linux fleet, with every alert explained in plain language.
          </p>

          <div className={styles.heroCtas}>
            <button
              className={styles.analyseBtn}
              onClick={() => {
                if (isAdmin) navigate('/admin/pending')
                else if (ia_user) navigate('/ai-dashboard')
                else if (soc_user) navigate('/dashboard')
              }}
            >
              <span>Open dashboard</span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
              </svg>
            </button>
            <a href="#about" className={styles.secondaryBtn}>
              Learn more
            </a>
          </div>

          {/* Inline stats strip — architecture, not fabricated live metrics */}
          <div className={styles.heroStats}>
            <div className={styles.heroStat}>
              <span className={styles.heroStatValue}>3</span>
              <span className={styles.heroStatLabel}>Log sources unified</span>
            </div>
            <div className={styles.heroStatDivider} />
            <div className={styles.heroStat}>
              <span className={styles.heroStatValue}>2</span>
              <span className={styles.heroStatLabel}>Detection engines</span>
            </div>
            <div className={styles.heroStatDivider} />
            <div className={styles.heroStat}>
              <span className={styles.heroStatValue} style={{color:'#4ade80'}}>0</span>
              <span className={styles.heroStatLabel}>Labels required</span>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════ About ═══════════ */}
      <section id="about" className={styles.section}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionTag}>// About</span>
          <h2 className={styles.sectionTitle}>What is Sentinel/IDS?</h2>
          <p className={styles.sectionText}>
            Sentinel/IDS is a Linux-focused intrusion detection platform built
            as a final-year engineering project (PFE 2026). It ingests security
            logs from across your fleet — authentication, system, and audit
            (auditd) events — through an ELK pipeline, then runs two
            complementary detection engines on them: Sigma rules to catch known
            attack patterns, and unsupervised machine-learning models that learn
            each host's normal behaviour and flag deviations no signature would
            catch. Every alert is enriched with a natural-language explanation,
            so operators understand what happened without reverse-engineering
            raw logs.
          </p>

          <div className={styles.featureGrid}>
            {[
              {
                icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="9 13 11 15 15 11"/></svg>,
                title: 'Sigma rule detection',
                desc:  'Known attack patterns — brute force, privilege escalation, suspicious execution — matched against your logs using the open Sigma standard.'
              },
              {
                icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>,
                title: 'Unsupervised ML detection',
                desc:  'Per-source autoencoders learn what normal looks like on each host and surface anomalies automatically — no labelled attack data required.'
              },
              {
                icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="13" y2="13"/></svg>,
                title: 'Explained alerts',
                desc:  'Every detection ships with a plain-language explanation of why it fired, turning raw signals into context an analyst can act on.'
              },
            ].map((f, i) => (
              <div key={i} className={styles.featureCard}>
                <div className={styles.featureIcon}>{f.icon}</div>
                <h3 className={styles.featureTitle}>{f.title}</h3>
                <p className={styles.featureDesc}>{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════ Testimonials ═══════════ */}
      <section id="testimonials" className={`${styles.section} ${styles.sectionAlt}`}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionTag}>// Testimonials</span>
          <h2 className={styles.sectionTitle}>From operators in the field</h2>
          {testimonials.length === 0 ? (
            <p className={styles.sectionText} style={{fontStyle:'italic', color:'#5a6478'}}>
              No testimonials yet. Be the first to share your feedback!
            </p>
          ) : (
            <div className={styles.testimonialGrid}>
              {testimonials.map(t => (
                <div key={t.id} className={styles.testimonialCard}>
                  {t.rating && (
                    <div className={styles.stars}>
                      {[1,2,3,4,5].map(s => (
                        <svg key={s} width="14" height="14" viewBox="0 0 24 24"
                          fill={s <= t.rating ? '#4ade80' : 'none'}
                          stroke={s <= t.rating ? '#4ade80' : '#3a4055'}
                          strokeWidth="1.8" strokeLinejoin="round">
                          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                        </svg>
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

      {/* ═══════════ Contact — non-admin only ═══════════ */}
      {!isAdmin && (
        <section id="contact" className={styles.section}>
          <div className={styles.sectionInner}>
            <div className={styles.contactGrid}>

              {/* Left — info panel */}
              <div className={styles.contactInfo}>
                <span className={styles.sectionTag}>// Contact</span>
                <h2 className={styles.sectionTitle}>Share your experience</h2>
                <p className={styles.sectionText}>
                  Your feedback helps the team harden the platform and guides
                  the roadmap. Approved testimonials appear above for other
                  operators to see.
                </p>

                <div className={styles.contactSteps}>
                  {[
                    { label: 'Write your feedback', desc: 'Share your honest experience operating the platform.' },
                    { label: 'Admin reviews it',    desc: 'The team reads every submission carefully before publishing.' },
                    { label: 'Get published',       desc: 'Once approved, your testimonial goes live for everyone to see.' },
                  ].map((s, i) => (
                    <div key={i} className={styles.contactStep}>
                      <div className={styles.contactStepNum}>{String(i + 1).padStart(2, '0')}</div>
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
                    <h3 className={styles.fbSuccessTitle}>Feedback submitted</h3>
                    <p className={styles.fbSuccessText}>Thank you for sharing your thoughts. You'll receive an email once it's been reviewed.</p>
                    <button className={styles.fbSuccessBtn} onClick={() => setFbStatus(null)}>Submit another</button>
                  </div>
                ) : (
                  <form onSubmit={handleFeedbackSubmit} className={styles.fbForm} noValidate>
                    <p className={styles.fbFormTitle}>
                      <span className={styles.fbFormTitleDot} />
                      Leave a testimonial
                    </p>

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
                          >
                            <svg width="22" height="22" viewBox="0 0 24 24"
                              fill={s <= (hoverRating || rating) ? '#4ade80' : 'none'}
                              stroke={s <= (hoverRating || rating) ? '#4ade80' : '#3a4055'}
                              strokeWidth="1.6" strokeLinejoin="round">
                              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                            </svg>
                          </button>
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
                              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                            </>
                        }
                      </button>
                    </div>
                  </form>
                )}
              </div>

            </div>
          </div>
        </section>
      )}

      <footer className={styles.footer}>
        <div className={styles.footerInner}>
          <div className={styles.footerLeft}>
            <span className={styles.footerDot} />
            <span>All sensors online · TLS 1.3</span>
          </div>
          <p>© 2026 Sentinel/IDS · PFE Project</p>
        </div>
      </footer>
    </div>
  )
}