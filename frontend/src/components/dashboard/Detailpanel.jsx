import { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import { dashboardService } from '../../services/api'

// ── DetailPanel en MODALE centrée avec fond flouté ──
const SEV_META = {
  CRITICAL: { text:"#dc2626", bg:"#fef2f2", border:"#fecaca" },
  HIGH:     { text:"#ea580c", bg:"#fff7ed", border:"#fed7aa" },
  MEDIUM:   { text:"#ca8a04", bg:"#fefce8", border:"#fef08a" },
  LOW:      { text:"#16a34a", bg:"#f0fdf4", border:"#bbf7d0" },
};
const SRC_COLOR = { both:"#6366f1", ae_only:"#3b82f6", sigma_only:"#8b5cf6" };

function SevBadge({ level }) {
  const k = (level||"").toUpperCase();
  const t = SEV_META[k]||{ text:"#64748b", bg:"#f1f5f9", border:"#e2e8f0" };
  return (
    <span style={{ padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:800,
      letterSpacing:"0.07em", textTransform:"uppercase", whiteSpace:"nowrap",
      color:t.text, background:t.bg, border:`1px solid ${t.border}` }}>
      {level||"—"}
    </span>
  );
}

function SrcBadge({ source }) {
  const c = SRC_COLOR[source]||"#64748b";
  const label = { both:"⚡ Both", ae_only:"AE only", sigma_only:"Σ Sigma" }[source]||source;
  return (
    <span style={{ padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:700,
      color:c, background:c+"18", border:`1px solid ${c}30`, whiteSpace:"nowrap" }}>
      {label}
    </span>
  );
}

function KV({ k, v }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between",
      marginBottom:7, fontSize:12 }}>
      <span style={{ color:"#64748b" }}>{k}</span>
      <span style={{ fontWeight:700, fontFamily:"monospace", color:"#1e293b" }}>{v}</span>
    </div>
  );
}

export default function DetailPanel({ item, onClose }) {
  const [detail, setDetail] = useState(item);
  const [loading, setLoading] = useState(false);

  useEffect(()=>{
    if (!item?.id || !item?.type) return;
    setLoading(true);
    dashboardService.getResultDetail(item.type, item.id)
      .then(d => { setDetail(d); setLoading(false); })
      .catch(()=>setLoading(false));
  },[item?.id]);

  // Fermeture avec la touche Échap
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const lvl = (detail?.severity||detail?.level||"").toUpperCase();

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
        style={{
          background:"#fff", borderRadius:14,
          width:"100%", maxWidth:640, maxHeight:"85vh",
          overflowY:"auto",
          boxShadow:"0 24px 64px rgba(0,0,0,0.32)",
        }}
      >
        {/* Header sticky */}
        <div style={{ padding:"14px 18px", borderBottom:"1px solid #f1f5f9",
          display:"flex", justifyContent:"space-between", alignItems:"center",
          position:"sticky", top:0, background:"#fff", zIndex:1 }}>
          <span style={{ fontWeight:800, fontSize:14, color:"#0f172a" }}>
            Détail événement
          </span>
          <button onClick={onClose} style={{ background:"#f1f5f9", border:"none",
            cursor:"pointer", width:28, height:28, borderRadius:8, fontSize:18,
            color:"#64748b", display:"flex", alignItems:"center", justifyContent:"center" }}>
            ×
          </button>
        </div>

        {loading ? (
          <div style={{ padding:32, textAlign:"center", color:"#94a3b8", fontSize:13 }}>
            Chargement…
          </div>
        ) : (
          <div style={{ padding:18 }}>
            <div style={{ display:"flex", gap:6, marginBottom:12, flexWrap:"wrap" }}>
              <SevBadge level={lvl} />
              <SrcBadge source={detail?.detection_source} />
            </div>

            <div style={{ fontWeight:700, fontSize:15, color:"#0f172a", marginBottom:4 }}>
              {detail?.title||detail?.log_source||"—"}
            </div>
            <div style={{ fontSize:11, color:"#94a3b8", fontFamily:"monospace", marginBottom:16 }}>
              {detail?.["@timestamp"]
                ? new Date(detail["@timestamp"]).toLocaleString("fr-FR")
                : "—"}
            </div>

            <div style={{ background:"#f8fafc", borderRadius:10, padding:14, marginBottom:16 }}>
              {[
                detail?.ae_mse_error     != null && ["MSE",        detail.ae_mse_error.toFixed(6)],
                detail?.ae_anomaly_score != null && ["Score AE",   (detail.ae_anomaly_score*100).toFixed(1)+"%"],
                detail?.ae_threshold     != null && ["Seuil",      detail.ae_threshold.toFixed(6)],
                detail?.hits             != null && ["Hits Sigma", detail.hits],
                detail?.tactic                   && ["MITRE",      detail.tactic],
                detail?.log_source               && ["Source log", detail.log_source],
              ].filter(Boolean).map(([k,v])=><KV key={k} k={k} v={v} />)}
            </div>

            {detail?.llm_explanation && (
              <div style={{ marginBottom:16 }}>
                <div style={{ fontSize:10, fontWeight:800, color:"#94a3b8",
                  textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:8 }}>
                  Analyse LLM
                </div>
                <div style={{ fontSize:12.5, color:"#1e293b", lineHeight:1.7,
                  background:"#eef2ff", borderRadius:10, padding:"14px 16px",
                  border:"1px solid #e0e7ff" }}>
                  {typeof detail.llm_explanation==="string"
                    ? <ReactMarkdown>{detail.llm_explanation}</ReactMarkdown>
                    : <pre style={{whiteSpace:"pre-wrap"}}>{JSON.stringify(detail.llm_explanation,null,2)}</pre>}
                </div>
              </div>
            )}

            {detail?.details?.length>0 && (
              <div>
                <div style={{ fontSize:10, fontWeight:800, color:"#94a3b8",
                  textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:8 }}>
                  Logs déclencheurs
                </div>
                {detail.details.slice(0,5).map((d,i)=>(
                  <div key={i} style={{ fontFamily:"monospace", fontSize:11, color:"#334155",
                    background:"#f8fafc", borderRadius:7, padding:"7px 10px",
                    marginBottom:5, border:"1px solid #e2e8f0", wordBreak:"break-all" }}>
                    {typeof d==="string"?d:JSON.stringify(d)}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}