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
        borderBottom:   "1px solid #e2e8f0",
        background:     "#fff",
        position:       "sticky",
        top:            0,
        zIndex:         100,
      }}>

        {/* ── Onglets ─────────────────────────────────────────────────────── */}
        <div style={{ display: "flex", gap: 24 }}>
          <span style={{
            fontSize: 14, fontWeight: 600, color: "#1d4ed8",
            borderBottom: "2px solid #1d4ed8", paddingBottom: 4,
          }}>
            Dashboard
          </span>
          <span style={{ fontSize: 14, color: "#64748b", cursor: "pointer" }}>
            Events
          </span>
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
                background: "#f8fafc",
                border:     "1px solid #e2e8f0",
                borderRadius: 8,
                padding:    "6px 12px",
                fontSize:   12,
                color:      "#475569",
                cursor:     "pointer",
                whiteSpace: "nowrap",
              }}
            >
              <span style={{
                width: 7, height: 7, borderRadius: "50%",
                background: "#059669", display: "inline-block", flexShrink: 0,
              }} />
              Dernière analyse : <strong style={{ marginLeft: 4 }}>{timeAgo(lastReport.finished_at)}</strong>
            </button>
          ) : (
            <span style={{
              fontSize: 12, color: "#94a3b8",
              background: "#f8fafc", border: "1px solid #e2e8f0",
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
              background: "#fff",
              border:     "1px solid #e2e8f0",
              borderRadius: 8,
              padding:    "7px 14px",
              fontSize:   13,
              color:      "#475569",
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
              background: "#fff",
              border:     "1px solid #e2e8f0",
              borderRadius: 8,
              padding:    "7px 14px",
              fontSize:   13,
              color:      statsReady ? "#475569" : "#cbd5e1",
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
              background: "#1d4ed8",
              border:     "none",
              borderRadius: 8,
              padding:    "8px 16px",
              fontSize:   13,
              fontWeight: 500,
              color:      "#fff",
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