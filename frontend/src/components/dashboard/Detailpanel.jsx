import { useEffect } from "react";
import ReactMarkdown from "react-markdown";

// ── DetailPanel en MODALE centrée avec fond flouté ──
// Contrat SOC : /results renvoie déjà TOUT ce qu'affiche ce panneau
// (mapper full=False → expert=null). Aucun second fetch nécessaire :
// on lit directement la row cliquée.
const SEV_META = {
  CRITICAL: { text:"var(--sev-critical)", bg:"var(--sev-critical-bg)" },
  HIGH:     { text:"var(--sev-high)",     bg:"var(--sev-high-bg)" },
  MEDIUM:   { text:"var(--sev-medium)",   bg:"var(--sev-medium-bg)" },
  LOW:      { text:"var(--sev-low)",      bg:"var(--sev-low-bg)" },
};
const SRC_COLOR = { cnn:"var(--det-cnn)", sigma:"var(--det-sigma)" };

function SevBadge({ level }) {
  const k = (level||"").toUpperCase();
  const t = SEV_META[k]||{ text:"var(--text-faint)", bg:"var(--surface-sunk)" };
  return (
    <span style={{ padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:800,
      letterSpacing:"0.07em", textTransform:"uppercase", whiteSpace:"nowrap",
      color:t.text, background:t.bg, border:`1px solid ${t.text}` }}>
      {level||"—"}
    </span>
  );
}

function SrcBadge({ source }) {
  const c = SRC_COLOR[source]||"var(--text-faint)";
  const label = { cnn:"CNN-AE", sigma:"Σ Sigma" }[source]||source;
  return (
    <span style={{ padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:700,
      color:c, background:"var(--surface-sunk)", border:`1px solid ${c}`, whiteSpace:"nowrap" }}>
      {label}
    </span>
  );
}

function KV({ k, v }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between",
      marginBottom:7, fontSize:12 }}>
      <span style={{ color:"var(--text-soft)" }}>{k}</span>
      <span style={{ fontWeight:700, fontFamily:"var(--font-mono)", color:"var(--text)" }}>{v}</span>
    </div>
  );
}

export default function DetailPanel({ item, onClose, theme }) {
  // La row contient déjà tout (expert=null en SOC) → pas d'état async.
  const detail = item;

  // Fermeture avec la touche Échap
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const lvl = (detail?.severity||"").toUpperCase();

  return (
    // ── OVERLAY plein écran, fond flouté ──
    <div
      onClick={onClose}
      style={{
        position:"fixed", inset:0, zIndex:1000,
        background:"rgba(15,23,42,0.45)",
        backdropFilter:"blur(4px)",
        WebkitBackdropFilter:"blur(4px)",
        display:"flex", alignItems:"center", justifyContent:"center",
        padding:24,
      }}
    >
      {/* ── BOÎTE centrée — stopPropagation pour ne pas fermer au clic dedans ── */}
      <div
        onClick={(e)=>e.stopPropagation()}
        className="dash-theme"
        data-theme={theme}
        style={{
          background:"var(--surface)", borderRadius:14,
          width:"100%", maxWidth:640, maxHeight:"85vh",
          overflowY:"auto",
          boxShadow:"var(--shadow-lg)",
          border:"1px solid var(--border-strong)",
        }}
      >
        {/* Header sticky */}
        <div style={{ padding:"14px 18px", borderBottom:"1px solid var(--border)",
          display:"flex", justifyContent:"space-between", alignItems:"center",
          position:"sticky", top:0, background:"var(--surface)", zIndex:1 }}>
          <span style={{ fontWeight:800, fontSize:14, color:"var(--text)" }}>
            Détail événement
          </span>
          <button onClick={onClose} style={{ background:"var(--surface-2)", border:"none",
            cursor:"pointer", width:28, height:28, borderRadius:8, fontSize:18,
            color:"var(--text-soft)", display:"flex", alignItems:"center", justifyContent:"center" }}>
            ×
          </button>
        </div>

        <div style={{ padding:18 }}>
          <div style={{ display:"flex", gap:6, marginBottom:12, flexWrap:"wrap" }}>
            <SevBadge level={lvl} />
            <SrcBadge source={detail?.type} />
          </div>

          <div style={{ fontWeight:700, fontSize:15, color:"var(--text)", marginBottom:4 }}>
            {detail?.title||detail?.log_source||"—"}
          </div>
          <div style={{ fontSize:11, color:"var(--text-faint)", fontFamily:"var(--font-mono)", marginBottom:16 }}>
            {detail?.event_time
              ? new Date(detail.event_time).toLocaleString("fr-FR")
              : "—"}
            {detail?.event_time_estimated ? "  · heure estimée (run)" : ""}
          </div>

          <div style={{ background:"var(--surface-2)", borderRadius:10, padding:14, marginBottom:16 }}>
            {[
              detail?.verdict          && ["Verdict",    detail.verdict],
              detail?.hits    != null  && ["Volume",     detail.hits],
              detail?.tactic           && ["MITRE",      detail.tactic],
              detail?.log_source       && ["Source log", detail.log_source],
              detail?.host             && ["Hôte",       detail.host],
              detail?.started_at       && ["Début",      new Date(detail.started_at).toLocaleString("fr-FR")],
              detail?.ended_at         && ["Fin",        new Date(detail.ended_at).toLocaleString("fr-FR")],
            ].filter(Boolean).map(([k,v])=><KV key={k} k={k} v={v} />)}
          </div>

          {detail?.explanation && (
            <div style={{ marginBottom:16 }}>
              <div style={{ fontSize:10, fontWeight:800, color:"var(--text-faint)",
                textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:8 }}>
                Analyse LLM
              </div>
              <div style={{ fontSize:12.5, color:"var(--text)", lineHeight:1.7,
                background:"var(--accent-soft)", borderRadius:10, padding:"14px 16px",
                border:"1px solid var(--border)" }}>
                {typeof detail.explanation==="string"
                  ? <ReactMarkdown>{detail.explanation}</ReactMarkdown>
                  : <pre style={{whiteSpace:"pre-wrap"}}>{JSON.stringify(detail.explanation,null,2)}</pre>}
              </div>
            </div>
          )}

          {/* expert.details : peuplé uniquement en vue Expert AI (full=True).
              En SOC expert=null → ce bloc reste masqué, comportement voulu. */}
          {detail?.expert?.details?.length>0 && (
            <div>
              <div style={{ fontSize:10, fontWeight:800, color:"var(--text-faint)",
                textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:8 }}>
                Logs déclencheurs
              </div>
              {detail.expert.details.slice(0,5).map((d,i)=>(
                <div key={i} style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-soft)",
                  background:"var(--surface-2)", borderRadius:7, padding:"7px 10px",
                  marginBottom:5, border:"1px solid var(--border)", wordBreak:"break-all" }}>
                  {typeof d==="string"?d:JSON.stringify(d)}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}