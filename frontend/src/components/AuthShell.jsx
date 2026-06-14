import styles from '../pages/LoginPage.module.css'


/*Le principe est celui du layout partagé : 
AuthShell dessine le cadre, et chaque page ne fournit que son contenu propre — la carte du milieu — via children :*/

export default function AuthShell({ children }) {
  return (
    <div className={styles.page}>
      <aside className={styles.sidebar}>
        <div className={styles.gridOverlay} aria-hidden="true" />

        <div className={styles.sidebarTop}>
          <div className={styles.logoMark}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#052e16" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div>
            <h1 className={styles.sidebarTitle}>SENTINEL/IDS</h1>
            <p className={styles.sidebarSub}>v2.4 · Linux threat detection</p>
          </div>
        </div>

        <div className={styles.headline}>
          <h2>Real-time anomaly<br />detection across<br />your Linux fleet.</h2>
          <p>Kernel-level monitoring, syscall analysis, and ML-driven intrusion alerts — all from one console.</p>
        </div>

        <div className={styles.graphWrap} aria-hidden="true">
          <svg viewBox="0 0 200 200" className={styles.graph}>
            <defs>
              <marker id="arr" viewBox="0 0 6 6" refX="5" refY="3" markerWidth="4" markerHeight="4" orient="auto">
                <path d="M0 0 L6 3 L0 6 Z" fill="#f87171" />
              </marker>
            </defs>
            <g stroke="rgba(74,222,128,0.2)" strokeWidth="0.8" fill="none">
              <line x1="100" y1="100" x2="40"  y2="40"  />
              <line x1="100" y1="100" x2="160" y2="35"  />
              <line x1="100" y1="100" x2="170" y2="105" />
              <line x1="100" y1="100" x2="155" y2="165" />
              <line x1="100" y1="100" x2="55"  y2="160" />
              <line x1="100" y1="100" x2="25"  y2="110" />
              <line x1="100" y1="100" x2="95"  y2="30"  />
              <line x1="160" y1="35"  x2="170" y2="105" stroke="rgba(248,113,113,0.5)" strokeDasharray="3 3" />
            </g>
            <circle r="2.5" fill="#4ade80"><animateMotion dur="2.5s" repeatCount="indefinite" path="M 100 100 L 40 40" /></circle>
            <circle r="2.5" fill="#fbbf24"><animateMotion dur="3s" repeatCount="indefinite" path="M 100 100 L 155 165" /></circle>
            <circle r="2" fill="#4ade80" opacity="0.7"><animateMotion dur="3.5s" repeatCount="indefinite" path="M 100 100 L 25 110" /></circle>
            <circle cx="100" cy="100" r="20" fill="none" stroke="#4ade80" strokeWidth="0.6" opacity="0.4" />
            <circle cx="100" cy="100" r="14" fill="#4ade80" />
            <text x="100" y="104" textAnchor="middle" fontFamily="ui-monospace, monospace" fontSize="10" fontWeight="700" fill="#052e16">IDS</text>
            <g fill="rgba(74,222,128,0.15)" stroke="#4ade80" strokeWidth="0.8">
              <circle cx="40" cy="40" r="7" /><circle cx="95" cy="30" r="7" /><circle cx="25" cy="110" r="7" /><circle cx="55" cy="160" r="7" /><circle cx="155" cy="165" r="7" />
            </g>
            <circle cx="160" cy="35" r="7" fill="rgba(251,191,36,0.18)" stroke="#fbbf24" strokeWidth="0.8" />
            <circle cx="170" cy="105" r="8" fill="rgba(248,113,113,0.2)" stroke="#f87171" strokeWidth="1" />
            <circle cx="170" cy="105" r="8" fill="none" stroke="#f87171" strokeWidth="0.6">
              <animate attributeName="r" values="8;15;8" dur="1.8s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.7;0;0.7" dur="1.8s" repeatCount="indefinite" />
            </circle>
            <g fontFamily="ui-monospace, monospace" fontSize="7" fill="#5a6478">
              <text x="22" y="28">node-01</text><text x="78" y="20">node-02</text><text x="142" y="22">node-03</text>
              <text x="178" y="103" fill="#f87171">⚠ node-04</text><text x="138" y="183">node-05</text><text x="34" y="178">node-06</text><text x="2" y="125">node-07</text>
            </g>
          </svg>
        </div>

        <p className={styles.sidebarFooter}>
          <span className={styles.statusDot} aria-hidden="true" />
          All sensors online · TLS 1.3 · MFA required
        </p>
      </aside>

      <main className={styles.main}>{children}</main>
    </div>
  )
}