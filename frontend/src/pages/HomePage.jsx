import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../context/ThemeContext.jsx'
import { feedbackService } from '../services/api.js'
import linuxSecurityImg from '../assets/linux-security.jpg'
import styles from './Homepage.module.css'
import '../styles/tokens.css'

// Explicit anchor map instead of auto-lowercasing labels.
// "About" now correctly points at the system explainer section
// (id="about-system"), not the hero itself (id="about" is only used
// as the hero's own landmark id).
const NAV_LINKS = [
  { label: 'About', href: '#about-system' },
  { label: 'Testimonials', href: '#testimonials' },
  { label: 'Contact', href: '#contact' },
]

export default function HomePage() {
  const { user, logout } = useAuth()
  const { theme } = useTheme()
  const navigate = useNavigate()

  const isAdmin = user?.role === 'admin'
  const specialty = user?.specialty

  const ia_user = specialty === 'ia_user'
  const soc_user = specialty === 'soc_user'

  const [dropdownOpen, setDropdownOpen] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const [testimonials, setTestimonials] = useState([])
  const [testimonialsState, setTestimonialsState] = useState('loading') // 'loading' | 'ok' | 'error'

  const [feedback, setFeedback] = useState('')
  const [rating, setRating] = useState(0)
  const [hoverRating, setHoverRating] = useState(0)
  const [fbStatus, setFbStatus] = useState(null)
  const [fbLoading, setFbLoading] = useState(false)

  const [contactName, setContactName] = useState('')
  const [contactEmail, setContactEmail] = useState('')
  const [contactMessage, setContactMessage] = useState('')
  const [contactStatus, setContactStatus] = useState(null)

  const dropdownRef = useRef(null)
  const avatarBtnRef = useRef(null)

  /*
   * ============================================================
   * Load approved testimonials
   * Distinguish "failed to load" from "genuinely empty" so the
   * empty state never lies about what happened.
   * ============================================================
   */
  useEffect(() => {
    let cancelled = false

    setTestimonialsState('loading')

    feedbackService
      .getApproved()
      .then(data => {
        if (cancelled) return
        setTestimonials(data)
        setTestimonialsState('ok')
      })
      .catch(() => {
        if (cancelled) return
        setTestimonialsState('error')
      })

    return () => {
      cancelled = true
    }
  }, [])

  /*
   * ============================================================
   * Close dropdown when clicking outside, or on Escape.
   * Return focus to the trigger button on close for keyboard users.
   * ============================================================
   */
  useEffect(() => {
    function handleClick(e) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target)
      ) {
        setDropdownOpen(false)
      }
    }

    function handleKeyDown(e) {
      if (e.key === 'Escape' && dropdownOpen) {
        setDropdownOpen(false)
        avatarBtnRef.current?.focus()
      }
    }

    document.addEventListener('mousedown', handleClick)
    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('mousedown', handleClick)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [dropdownOpen])

  /*
   * ============================================================
   * Navigation
   * ============================================================
   */
  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  const handleOpenDashboard = useCallback(() => {
    if (isAdmin) {
      navigate('/admin/pending')
    } else if (ia_user) {
      navigate('/ai-dashboard')
    } else if (soc_user) {
      navigate('/dashboard')
    } else {
      navigate('/dashboard')
    }
  }, [isAdmin, ia_user, soc_user, navigate])

  function handleProfile() {
    navigate('/profile')
    setDropdownOpen(false)
  }

  function handleMobileNavClick() {
    setMobileMenuOpen(false)
  }

  /*
   * ============================================================
   * Feedback submission
   * ============================================================
   */
  async function handleFeedbackSubmit(e) {
    e.preventDefault()

    if (!feedback.trim()) {
      return
    }

    setFbLoading(true)
    setFbStatus(null)

    try {
      await feedbackService.submit(
        feedback,
        rating || null
      )

      setFbStatus('sent')
      setFeedback('')
      setRating(0)
      setHoverRating(0)
    } catch {
      setFbStatus('error')
    } finally {
      setFbLoading(false)
    }
  }

  /*
   * ============================================================
   * Contact form
   *
   * This still opens the user's mail client. That approach fails
   * silently on machines with no configured mail client (common on
   * shared/work devices and some mobile browsers), so we can't
   * treat it as a confirmed delivery — the success message is
   * worded to reflect that, and the fields reset afterwards so the
   * form doesn't look "stuck" if the person wants to send another.
   *
   * TODO(product): route this through feedbackService or a real
   * /contact API endpoint once one exists, so failures can be
   * detected and reported like the feedback form does.
   * ============================================================
   */
  const CONTACT_EMAIL = 'contact@sentinel-ids.com'

  function handleContactSubmit(e) {
    e.preventDefault()

    if (
      !contactName.trim() ||
      !contactEmail.trim() ||
      !contactMessage.trim()
    ) {
      return
    }

    const subject = encodeURIComponent(
      `Sentinel/IDS contact from ${contactName}`
    )

    const body = encodeURIComponent(
      `Name: ${contactName}\n` +
      `Email: ${contactEmail}\n\n` +
      `${contactMessage}`
    )

    window.location.href =
      `mailto:${CONTACT_EMAIL}?subject=${subject}&body=${body}`

    setContactStatus('sent')
    setContactName('')
    setContactEmail('')
    setContactMessage('')
  }

  /*
   * ============================================================
   * User information
   * ============================================================
   */
  const initials =
    user?.email?.[0]?.toUpperCase() ?? 'A'

  const roleLabel =
    isAdmin
      ? 'Administrator'
      : soc_user
        ? 'SOC Operator'
        : ia_user
          ? 'IA Analyst'
          : user?.role || 'Operator'

  const dashboardLabel = isAdmin
    ? 'Admin dashboard'
    : ia_user
      ? 'AI dashboard'
      : 'Dashboard'

  /*
   * ============================================================
   * System capabilities
   * ============================================================
   */
  const capabilities = [
    {
      type: 'detection',
      title: 'Anomaly Detection',
      description:
        'Identify unusual behaviour that deviates from normal Linux system activity and may indicate a potential security threat.',
      icon: (
        <svg
          width="22"
          height="22"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M3 12h4l2-8 4 16 2-8h6" />
        </svg>
      ),
    },
    {
      type: 'attack',
      title: 'Attack Detection',
      description:
        'Detect suspicious patterns associated with known attacks and malicious activities targeting Linux environments.',
      icon: (
        <svg
          width="22"
          height="22"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M12 8v4" />
          <path d="M12 16h.01" />
        </svg>
      ),
    },
    {
      type: 'explanation',
      title: 'Explained Alerts',
      description:
        'Turn detected events into clear and contextual explanations that help analysts understand what happened.',
      icon: (
        <svg
          width="22"
          height="22"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          <line x1="8" y1="9" x2="16" y2="9" />
          <line x1="8" y1="13" x2="14" y2="13" />
        </svg>
      ),
    },
  ]

  return (
    <div className={`${styles.page} dash-theme`} data-theme={theme}>

      {/* ======================================================
          NAVBAR
      ======================================================= */}
      <header className={styles.navbar}>

        <div className={styles.navLogo}>
          <div className={styles.logoMark}>
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#052e16"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>

          <div className={styles.logoTextWrap}>
            <span className={styles.logoText}>
              SENTINEL/IDS
            </span>

            <span className={styles.logoTag}>
              Linux Security
            </span>
          </div>
        </div>

        <nav className={styles.navLinks}>
          {NAV_LINKS.map(link => (
            <a
              key={link.label}
              href={link.href}
              className={styles.navLink}
            >
              {link.label}
            </a>
          ))}
        </nav>

        <div className={styles.navRightGroup}>

          {/* Primary action for returning, authenticated users: get
              straight to their workspace instead of hunting for it
              inside the account dropdown. */}
          {user && (
            <button
              className={styles.dashboardBtn}
              onClick={handleOpenDashboard}
            >
              {dashboardLabel}
            </button>
          )}

          <div
            className={styles.navRight}
            ref={dropdownRef}
          >
            <button
              ref={avatarBtnRef}
              className={styles.avatarBtn}
              onClick={() =>
                setDropdownOpen(value => !value)
              }
              aria-label="User menu"
              aria-haspopup="menu"
              aria-expanded={dropdownOpen}
            >
              <span className={styles.avatarWrap}>
                <span className={styles.avatar}>
                  {initials}
                </span>

                <span
                  className={styles.statusPing}
                  aria-hidden="true"
                />
              </span>

              <svg
                className={`${styles.chevron} ${
                  dropdownOpen
                    ? styles.chevronOpen
                    : ''
                }`}
                width="13"
                height="13"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polyline points="6 9 12 15 18 9" />
              </svg>
            </button>

            {dropdownOpen && (
              <div className={styles.dropdown} role="menu">

                <div className={styles.dropdownHeader}>
                  <span className={styles.dropdownEmail}>
                    {user?.email}
                  </span>

                  <span className={styles.dropdownRole}>
                    <span className={styles.roleDot} />
                    {roleLabel}
                  </span>
                </div>

                <div className={styles.dropdownDivider} />

                <button
                  className={styles.dropdownItem}
                  onClick={handleProfile}
                  role="menuitem"
                >
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>

                  Profile
                </button>

                {isAdmin && (
                  <button
                    className={styles.dropdownItem}
                    onClick={() => {
                      navigate('/admin/pending')
                      setDropdownOpen(false)
                    }}
                    role="menuitem"
                  >
                    <svg
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <rect x="3" y="3" width="7" height="9" />
                      <rect x="14" y="3" width="7" height="5" />
                      <rect x="14" y="12" width="7" height="9" />
                      <rect x="3" y="16" width="7" height="5" />
                    </svg>

                    Admin dashboard
                  </button>
                )}

                {ia_user && (
                  <button
                    className={styles.dropdownItem}
                    onClick={() => {
                      navigate('/ai-dashboard')
                      setDropdownOpen(false)
                    }}
                    role="menuitem"
                  >
                    <svg
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z" />
                      <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0-.34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z" />
                    </svg>

                    AI Dashboard
                  </button>
                )}

                {soc_user && (
                  <button
                    className={styles.dropdownItem}
                    onClick={() => {
                      navigate('/dashboard')
                      setDropdownOpen(false)
                    }}
                    role="menuitem"
                  >
                    <svg
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <rect x="3" y="3" width="7" height="9" />
                      <rect x="14" y="3" width="7" height="5" />
                      <rect x="14" y="12" width="7" height="9" />
                      <rect x="3" y="16" width="7" height="5" />
                    </svg>

                    SOC Dashboard
                  </button>
                )}

                <div className={styles.dropdownDivider} />

                <button
                  className={`${styles.dropdownItem} ${styles.dropdownLogout}`}
                  onClick={handleLogout}
                  role="menuitem"
                >
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                    <polyline points="16 17 21 12 16 7" />
                    <line x1="21" y1="12" x2="9" y2="12" />
                  </svg>

                  Log out
                </button>

              </div>
            )}
          </div>

          {/* Mobile nav toggle — .navLinks is hidden below 640px via
              CSS, so this is the only way to reach Testimonials /
              Contact on small screens. */}
          <button
            className={styles.mobileMenuBtn}
            onClick={() => setMobileMenuOpen(v => !v)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            )}
          </button>

        </div>

        {mobileMenuOpen && (
          <div className={styles.mobileMenu}>
            {NAV_LINKS.map(link => (
              <a
                key={link.label}
                href={link.href}
                className={styles.mobileMenuLink}
                onClick={handleMobileNavClick}
              >
                {link.label}
              </a>
            ))}

            {user && (
              <button
                className={styles.mobileMenuDashboard}
                onClick={() => {
                  handleMobileNavClick()
                  handleOpenDashboard()
                }}
              >
                {dashboardLabel}
              </button>
            )}
          </div>
        )}
      </header>


      {/* ======================================================
          SECTION 01 — LINUX SECURITY
      ======================================================= */}
      <section
        id="about"
        className={styles.hero}
      >
        <div
          className={styles.heroGrid}
          aria-hidden="true"
        />

        <div
          className={styles.heroGlow}
          aria-hidden="true"
        />

        <div className={styles.heroLayout}>

          <div className={styles.heroCopy}>

            <div className={styles.heroEyebrow}>
              <span className={styles.heroEyebrowDot} />
              <span>LINUX SECURITY</span>
            </div>

            <h1 className={styles.heroTitle}>
              Securing Linux systems
              <em> against evolving threats.</em>
            </h1>

            <p className={styles.heroSub}>
              Linux systems power servers, cloud
              infrastructures and critical services.
              Their continuous exposure to cyber threats
              makes effective monitoring and detection
              essential.
            </p>

            <p className={styles.heroSubSecondary}>
              Sentinel/IDS helps identify abnormal
              behaviour and potential attacks by
              continuously analysing Linux system activity.
            </p>

            <div className={styles.heroCtas}>

              {user ? (
                <button
                  className={styles.primaryBtn}
                  onClick={handleOpenDashboard}
                >
                  <span>
                    Open {dashboardLabel.toLowerCase()}
                  </span>

                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <line x1="5" y1="12" x2="19" y2="12" />
                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                </button>
              ) : (
                <button
                  className={styles.primaryBtn}
                  onClick={() => {
                    document
                      .getElementById('about-system')
                      ?.scrollIntoView({
                        behavior: 'smooth'
                      })
                  }}
                >
                  <span>
                    Discover our system
                  </span>

                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <line
                      x1="5"
                      y1="12"
                      x2="19"
                      y2="12"
                    />

                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                </button>
              )}

              <a
                href="#contact"
                className={styles.secondaryBtn}
              >
                Contact us
              </a>

            </div>

          </div>


          <div className={styles.heroImageSide}>

            <div className={styles.heroImageFrame}>

              <img
                src={linuxSecurityImg}
                alt="Linux system security"
                className={styles.heroImage}
              />

              <div className={styles.imageOverlay} />

              <div className={styles.imageStatus}>
                <span
                  className={styles.imageStatusDot}
                />

                <span>
                  Linux security
                </span>
              </div>

            </div>

          </div>

        </div>
      </section>


      {/* ======================================================
          SECTION 02 — OUR SYSTEM
      ======================================================= */}
      <section
        id="about-system"
        className={styles.section}
      >
        <div className={styles.sectionInner}>

          <span className={styles.sectionTag}>
            // Our system
          </span>

          <h2 className={styles.sectionTitle}>
            Security monitoring for
            <span> Linux environments.</span>
          </h2>

          <p className={styles.sectionText}>
            Sentinel/IDS monitors Linux environments
            and identifies both abnormal behaviours and
            suspicious attack patterns. The platform
            combines automated detection with contextual
            explanations to help analysts understand
            security events more effectively.
          </p>


          <div className={styles.featureGrid}>

            {capabilities.map((feature, index) => (
              <div
                key={feature.type}
                className={styles.featureCard}
              >

                <div
                  className={`${styles.featureIcon} ${
                    feature.type === 'attack'
                      ? styles.featureIconWarning
                      : feature.type === 'explanation'
                        ? styles.featureIconNeutral
                        : ''
                  }`}
                >
                  {feature.icon}
                </div>

                <span className={styles.featureNumber}>
                  0{index + 1}
                </span>

                <h3 className={styles.featureTitle}>
                  {feature.title}
                </h3>

                <p className={styles.featureDesc}>
                  {feature.description}
                </p>

              </div>
            ))}

          </div>


          <div className={styles.systemHighlights}>

            <div className={styles.highlightItem}>
              <span className={styles.highlightValue}>
                Linux
              </span>

              <span className={styles.highlightLabel}>
                Security focus
              </span>
            </div>

            <div className={styles.highlightDivider} />

            <div className={styles.highlightItem}>
              <span className={styles.highlightValue}>
                3
              </span>

              <span className={styles.highlightLabel}>
                Log sources
              </span>
            </div>

            <div className={styles.highlightDivider} />

            <div className={styles.highlightItem}>
              <span className={styles.highlightValue}>
                ML
              </span>

              <span className={styles.highlightLabel}>
                Behaviour analysis
              </span>
            </div>

            <div className={styles.highlightDivider} />

            <div className={styles.highlightItem}>
              <span className={styles.highlightValue}>
                AI
              </span>

              <span className={styles.highlightLabel}>
                Alert explanation
              </span>
            </div>

          </div>

        </div>
      </section>


      {/* ======================================================
          SECTION 03 — TESTIMONIALS
      ======================================================= */}
      <section
        id="testimonials"
        className={`${styles.section} ${styles.sectionAlt}`}
      >
        <div className={styles.sectionInner}>

          <span className={styles.sectionTag}>
            // Approved feedback
          </span>

          <h2 className={styles.sectionTitle}>
            What users say about
            <span> Sentinel/IDS.</span>
          </h2>

          <p className={styles.sectionText}>
            Feedback from users helps us evaluate the
            platform and identify opportunities for
            improvement.
          </p>

          {testimonialsState === 'loading' && (
            <div className={styles.testimonialGrid}>
              {[0, 1].map(i => (
                <div
                  key={i}
                  className={styles.testimonialSkeleton}
                  aria-hidden="true"
                />
              ))}
            </div>
          )}

          {testimonialsState === 'error' && (
            <div className={styles.testimonialEmpty}>
              <div className={styles.emptyIcon}>
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.7"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
              </div>

              <h3>
                Couldn't load testimonials.
              </h3>

              <p>
                There was a problem reaching the server.
                Refresh the page to try again.
              </p>
            </div>
          )}

          {testimonialsState === 'ok' && (
            testimonials.length === 0 ? (

              <div className={styles.testimonialEmpty}>

                <div className={styles.emptyIcon}>
                  <svg
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.7"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
                  </svg>
                </div>

                <h3>
                  No approved feedback yet.
                </h3>

                <p>
                  Your experience can help us improve
                  the platform.
                </p>

              </div>

            ) : (

              <div className={styles.testimonialGrid}>

                {testimonials.map((testimonial) => (

                  <article
                    key={testimonial.id}
                    className={styles.testimonialCard}
                  >

                    <div className={styles.testimonialTop}>

                      {testimonial.rating && (
                        <div className={styles.stars}>

                          {[1, 2, 3, 4, 5].map(star => (

                            <svg
                              key={star}
                              width="15"
                              height="15"
                              viewBox="0 0 24 24"
                              fill={
                                star <= testimonial.rating
                                  ? '#4ade80'
                                  : 'none'
                              }
                              stroke={
                                star <= testimonial.rating
                                  ? '#4ade80'
                                  : '#3a4055'
                              }
                              strokeWidth="1.8"
                            >
                              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                            </svg>

                          ))}

                        </div>
                      )}

                      <span className={styles.approvedBadge}>
                        Approved
                      </span>

                    </div>


                    <p className={styles.testimonialText}>
                      "{testimonial.message}"
                    </p>


                    <div className={styles.testimonialAuthor}>

                      <div className={styles.testimonialAvatar}>
                        {testimonial.user_name?.[0]?.toUpperCase() || 'U'}
                      </div>

                      <div>
                        <p className={styles.testimonialName}>
                          {testimonial.user_name}
                        </p>

                        <p className={styles.testimonialRole}>
                          Sentinel/IDS user
                        </p>
                      </div>

                    </div>

                  </article>

                ))}

              </div>
            )
          )}


          {/* Leave feedback */}
          {!isAdmin && (
            <div className={styles.feedbackArea}>

              {fbStatus === 'sent' ? (

                <div className={styles.fbSuccess}>

                  <div className={styles.fbSuccessIcon}>
                    <svg
                      width="24"
                      height="24"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  </div>

                  <div>
                    <h3>
                      Feedback submitted
                    </h3>

                    <p>
                      Thank you. Your feedback will be
                      reviewed before publication.
                    </p>
                  </div>

                  <button
                    className={styles.fbResetBtn}
                    onClick={() => setFbStatus(null)}
                  >
                    Submit another
                  </button>

                </div>

              ) : (

                <form
                  className={styles.feedbackForm}
                  onSubmit={handleFeedbackSubmit}
                  noValidate
                >

                  <div className={styles.feedbackFormHeader}>

                    <div>
                      <span className={styles.miniTag}>
                        Share your experience
                      </span>

                      <h3>
                        Help us improve Sentinel/IDS.
                      </h3>
                    </div>

                  </div>


                  <div className={styles.ratingBlock}>

                    <label>
                      Rate your experience
                      <span className={styles.optionalTag}>
                        (optional)
                      </span>
                    </label>

                    <div className={styles.starRow}>

                      {[1, 2, 3, 4, 5].map(star => (

                        <button
                          key={star}
                          type="button"
                          className={`${styles.starBtn} ${
                            star <=
                            (hoverRating || rating)
                              ? styles.starActive
                              : ''
                          }`}
                          onMouseEnter={() =>
                            setHoverRating(star)
                          }
                          onMouseLeave={() =>
                            setHoverRating(0)
                          }
                          onClick={() =>
                            setRating(current =>
                              current === star
                                ? 0
                                : star
                            )
                          }
                          aria-label={`Rate ${star} star${
                            star > 1 ? 's' : ''
                          }`}
                        >
                          <svg
                            width="21"
                            height="21"
                            viewBox="0 0 24 24"
                            fill={
                              star <=
                              (hoverRating || rating)
                                ? '#4ade80'
                                : 'none'
                            }
                            stroke={
                              star <=
                              (hoverRating || rating)
                                ? '#4ade80'
                                : '#3a4055'
                            }
                            strokeWidth="1.6"
                          >
                            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                          </svg>
                        </button>

                      ))}

                    </div>

                  </div>


                  <div className={styles.feedbackField}>

                    <div className={styles.feedbackFieldHeader}>

                      <label>
                        Your message
                      </label>

                      <span>
                        {feedback.length}/500
                      </span>

                    </div>

                    <textarea
                      value={feedback}
                      maxLength={500}
                      rows={4}
                      placeholder="Share your experience with Sentinel/IDS..."
                      onChange={e => {
                        setFeedback(e.target.value)
                        setFbStatus(null)
                      }}
                      required
                    />

                  </div>


                  {fbStatus === 'error' && (
                    <div className={styles.fbError}>
                      Something went wrong.
                      Please try again.
                    </div>
                  )}


                  <button
                    type="submit"
                    className={styles.feedbackSubmit}
                    disabled={
                      fbLoading ||
                      !feedback.trim()
                    }
                  >
                    {fbLoading ? (
                      <>
                        <span className={styles.fbSpinner} />
                        Sending...
                      </>
                    ) : (
                      <>
                        Submit feedback

                        <svg
                          width="14"
                          height="14"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <line
                            x1="5"
                            y1="12"
                            x2="19"
                            y2="12"
                          />
                          <polyline points="12 5 19 12 12 19" />
                        </svg>
                      </>
                    )}
                  </button>

                </form>

              )}

            </div>
          )}

        </div>
      </section>


      {/* ======================================================
          SECTION 04 — CONTACT
      ======================================================= */}
      <section
        id="contact"
        className={styles.contactSection}
      >
        <div className={styles.sectionInner}>

          <div className={styles.contactGrid}>

            <div className={styles.contactInfo}>

              <span className={styles.sectionTag}>
                // Contact
              </span>

              <h2 className={styles.contactTitle}>
                Get in touch with
                <span> Sentinel/IDS.</span>
              </h2>

              <p className={styles.contactText}>
                Have a question about the platform,
                the project, or our approach to Linux
                security? We would be happy to hear
                from you.
              </p>


              <div className={styles.contactDetails}>

                <div className={styles.contactDetail}>

                  <div className={styles.contactDetailIcon}>
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <rect
                        x="3"
                        y="5"
                        width="18"
                        height="14"
                        rx="2"
                      />

                      <polyline points="3 7 12 13 21 7" />
                    </svg>
                  </div>

                  <div>
                    <span>
                      Email
                    </span>

                    <a
                      href={`mailto:${CONTACT_EMAIL}`}
                    >
                      {CONTACT_EMAIL}
                    </a>
                  </div>

                </div>


                <div className={styles.contactDetail}>

                  <div className={styles.contactDetailIcon}>
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M12 2v20" />
                      <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H7" />
                    </svg>
                  </div>

                  <div>
                    <span>
                      Project
                    </span>

                    <strong>
                      Sentinel/IDS
                    </strong>
                  </div>

                </div>


                <div className={styles.contactDetail}>

                  <div className={styles.contactDetailIcon}>
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M12 2a10 10 0 1 0 10 10" />
                      <path d="M12 6v6l4 2" />
                    </svg>
                  </div>

                  <div>
                    <span>
                      Focus
                    </span>

                    <strong>
                      Linux Security & AI
                    </strong>
                  </div>

                </div>

              </div>

            </div>


            <div className={styles.contactFormWrap}>

              <form
                className={styles.contactForm}
                onSubmit={handleContactSubmit}
              >

                <div className={styles.contactFormHeader}>

                  <span className={styles.formStatusDot} />

                  <span>
                    Send a message
                  </span>

                </div>


                <div className={styles.formRow}>

                  <div className={styles.formField}>

                    <label htmlFor="contact-name">
                      Name
                    </label>

                    <input
                      id="contact-name"
                      type="text"
                      value={contactName}
                      onChange={e =>
                        setContactName(e.target.value)
                      }
                      placeholder="Your name"
                      required
                    />

                  </div>


                  <div className={styles.formField}>

                    <label htmlFor="contact-email">
                      Email
                    </label>

                    <input
                      id="contact-email"
                      type="email"
                      value={contactEmail}
                      onChange={e =>
                        setContactEmail(e.target.value)
                      }
                      placeholder="you@example.com"
                      required
                    />

                  </div>

                </div>


                <div className={styles.formField}>

                  <label htmlFor="contact-message">
                    Message
                  </label>

                  <textarea
                    id="contact-message"
                    value={contactMessage}
                    onChange={e =>
                      setContactMessage(e.target.value)
                    }
                    placeholder="How can we help you?"
                    rows={6}
                    required
                  />

                </div>


                {contactStatus === 'sent' && (
                  <div className={styles.contactSuccess}>
                    Your email client should now have
                    opened with the message pre-filled.
                    Nothing arrives until you actually
                    send it from there.
                  </div>
                )}


                <button
                  type="submit"
                  className={styles.contactSubmit}
                >
                  Send message

                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <line
                      x1="5"
                      y1="12"
                      x2="19"
                      y2="12"
                    />

                    <polyline points="12 5 19 12 12 19" />
                  </svg>

                </button>

              </form>

            </div>

          </div>

        </div>
      </section>


      {/* ======================================================
          FOOTER
      ======================================================= */}
      <footer className={styles.footer}>

        <div className={styles.footerInner}>

          <div className={styles.footerBrand}>

            <div className={styles.footerLogo}>
              <span className={styles.footerLogoDot} />
              SENTINEL/IDS
            </div>

            <p>
              Linux security monitoring and
              intelligent threat detection.
            </p>

          </div>


          <div className={styles.footerLinks}>

            <a href="#about">
              About
            </a>

            <a href="#testimonials">
              Testimonials
            </a>

            <a href="#contact">
              Contact
            </a>

          </div>


          <div className={styles.footerRight}>

            <span className={styles.footerStatus}>
              <span className={styles.footerStatusDot} />
              System online
            </span>

            <span>
              © 2026 Sentinel/IDS
            </span>

          </div>

        </div>

      </footer>

    </div>
  )
}