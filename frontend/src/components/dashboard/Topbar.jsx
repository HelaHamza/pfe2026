/**
 * components/dashboard/Topbar.jsx
 *
 * Props :
 *   onRefresh          — actualiser le dashboard
 *   loading            — spinner actualiser
 *   onShowLastReport   — rouvrir le modal indicateur
 *   onLaunchNew        — lancer une nouvelle analyse
 *   onDownloadReport   — télécharger le rapport JSON
 *   lastReport         — dernier report MongoDB (pour l'indicateur date)
 *   statsReady         — true quand les stats ES sont chargées (active le bouton télécharger)
 */

function timeAgo(iso) {
  if (!iso) return "";
  const diff = Math.round((Date.now() - new Date(iso)) / 60000);
  if (diff < 1)    return "à l'instant";
  if (diff < 60)   return `il y a ${diff} min`;
  if (diff < 1440) return `il y a ${Math.floor(diff / 60)}h`;
  return `il y a ${Math.floor(diff / 1440)}j`;
}

export default function TopBar({
  onRefresh,
  loading,
  onShowLastReport,
  onLaunchNew,
  onDownloadReport,
  lastReport,
  statsReady,
}) {
  return (
    <>
      <div style={{
        display:        "flex",
        alignItems:     "center",
        justifyContent: "space-between",
        padding:        "12px 24px",
        borderBottom:   "1px solid var(--border-strong)",
        background:     "var(--surface)",
        position:       "sticky",
        top:            0,
        zIndex:         100,
      }}>

        {/* ── Onglets ─────────────────────────────────────────────────────── */}
        <div style={{ display: "flex", gap: 24 }}>
          {/* <span style={{
            fontSize: 14, fontWeight: 600, color: "var(--accent)",
            borderBottom: "2px solid var(--accent)", paddingBottom: 4,
          }}>
            Dashboard
          </span> */}
          
        </div>

        {/* ── Actions ─────────────────────────────────────────────────────── */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>

          {/* Indicateur "Dernière analyse : il y a X min" */}
          {lastReport?.finished_at ? (
            <button
              onClick={onShowLastReport}
              title="Voir le résumé de la dernière analyse"
              style={{
                display:    "flex",
                alignItems: "center",
                gap:        6,
                background: "var(--surface-2)",
                border:     "1px solid var(--border)",
                borderRadius: 8,
                padding:    "6px 12px",
                fontSize:   12,
                color:      "var(--text-soft)",
                cursor:     "pointer",
                whiteSpace: "nowrap",
              }}
            >
              <span style={{
                width: 7, height: 7, borderRadius: "50%",
                background: "var(--accent)", display: "inline-block", flexShrink: 0,
              }} />
              Dernière analyse : <strong style={{ marginLeft: 4 }}>{timeAgo(lastReport.finished_at)}</strong>
            </button>
          ) : (
            <span style={{
              fontSize: 12, color: "var(--text-faint)",
              background: "var(--surface-2)", border: "1px solid var(--border)",
              borderRadius: 8, padding: "6px 12px", whiteSpace: "nowrap",
            }}>
              Aucune analyse enregistrée
            </span>
          )}

          {/* Actualiser */}
          <button
            onClick={onRefresh}
            disabled={loading}
            style={{
              display:    "flex",
              alignItems: "center",
              gap:        5,
              background: "var(--surface)",
              border:     "1px solid var(--border)",
              borderRadius: 8,
              padding:    "7px 14px",
              fontSize:   13,
              color:      "var(--text-soft)",
              cursor:     loading ? "wait" : "pointer",
              opacity:    loading ? 0.6 : 1,
            }}
          >
            <span style={{
              display:   "inline-block",
              animation: loading ? "spin 1s linear infinite" : "none",
            }}>↻</span>
            Actualiser
          </button>

          {/* Télécharger rapport */}
          <button
            onClick={onDownloadReport}
            disabled={!statsReady}
            title={statsReady ? "Télécharger le rapport de la dernière analyse" : "Attendez le chargement des stats"}
            style={{
              display:    "flex",
              alignItems: "center",
              gap:        5,
              background: "var(--surface)",
              border:     "1px solid var(--border)",
              borderRadius: 8,
              padding:    "7px 14px",
              fontSize:   13,
              color:      statsReady ? "var(--text-soft)" : "var(--text-faint)",
              cursor:     statsReady ? "pointer" : "not-allowed",
            }}
          >
            ⬇ Télécharger rapport
          </button>

          {/* Lancer l'analyse */}
          <button
            onClick={onLaunchNew}
            style={{
              display:    "flex",
              alignItems: "center",
              gap:        5,
              background: "var(--accent)",
              border:     "none",
              borderRadius: 8,
              padding:    "8px 16px",
              fontSize:   13,
              fontWeight: 500,
              color:      "var(--bg)",
              cursor:     "pointer",
            }}
          >
            ▶ Lancer l'analyse
          </button>

        </div>
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
      `}</style>
    </>
  );
}