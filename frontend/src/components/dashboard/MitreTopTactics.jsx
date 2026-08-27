import { mitre as mitreColors } from "../../theme/colors";

// Techniques ATT&CK produites par tes règles Sigma → nom lisible (FR).
// Le code reste affiché en secondaire pour la rigueur.
// Complète cette table au fil de tes règles ; toute technique absente
// retombe proprement sur son code brut.
const ATTCK = {
  "T1078":     { name: "Comptes valides",             tactic: "Accès initial" },
  "T1078.003": { name: "Comptes valides — locaux",    tactic: "Accès initial" },
  "T1110":     { name: "Force brute",                 tactic: "Accès aux identifiants" },
  "T1110.001": { name: "Force brute — mot de passe",  tactic: "Accès aux identifiants" },
  "T1021.004": { name: "Service distant — SSH",       tactic: "Mouvement latéral" },
  "T1046":     { name: "Scan de services réseau",     tactic: "Découverte" },
  "T1548":     { name: "Élévation via mécanisme",     tactic: "Élévation de privilèges" },
  "T1548.003": { name: "Abus de sudo",                tactic: "Élévation de privilèges" },
  "T1070":     { name: "Effacement de traces",        tactic: "Évasion défensive" },
  "T1070.006": { name: "Horodatage falsifié",         tactic: "Évasion défensive" },
  "T1059":     { name: "Interpréteur de commandes",   tactic: "Exécution" },
  "T1543":     { name: "Service système créé/modifié", tactic: "Persistance" },
  "T1053":     { name: "Tâche planifiée",             tactic: "Exécution" },
  "T1136":     { name: "Création de compte",          tactic: "Persistance" },
};

function describe(code) {
  const key = String(code || "").trim();
  const meta = ATTCK[key] || ATTCK[key.split(".")[0]];   // fallback sur la technique parente
  return meta || { name: null, tactic: null };
}

export default function MitreTopTactics({ data, limit = 8 }) {
  const items = (data || [])
    .map((d) => {
      const code = d.tactic || d.level || "Inconnu";
      const { name, tactic } = describe(code);
      return { code, name, tactic, count: d.count ?? 0 };
    })
    .filter((d) => d.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

  const max = items.length ? items[0].count : 1;

  return (
    <div className="card" style={{ minHeight: 220 }}>
      <div className="card__head" style={{ marginBottom: 4 }}>
        <h3 className="card__title">
          MITRE ATT&amp;CK · top techniques
        </h3>
        {items.length > 0 && (
          <span className="card__hint">
            top {items.length}
          </span>
        )}
      </div>
      <p style={{ margin: "0 0 var(--sp-4)", fontSize: 11, color: "var(--text-soft)" }}>
        Techniques détectées, classées par nombre d'alertes
      </p>

      {items.length === 0 ? (
        <div style={{
          fontSize: 12, color: "var(--text-faint)",
          textAlign: "center", padding: "30px 0",
        }}>
          Aucune technique détectée sur ce run
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {items.map((d, i) => {
            const color = mitreColors[i % mitreColors.length];
            return (
              <div key={d.code} style={{
                display: "flex", alignItems: "center", gap: 10,
                fontSize: 12, color: "var(--text)",
              }}>
                <span style={{
                  width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                  background: color,
                }} />

                {/* Nom lisible en principal, code + tactique en secondaire */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                    fontWeight: 500,
                  }} title={d.name ? `${d.name} (${d.code})` : d.code}>
                    {d.name || d.code}
                  </div>
                  <div style={{
                    fontSize: 10, color: "var(--text-faint)",
                    whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                  }}>
                    {d.code}{d.tactic ? ` · ${d.tactic}` : ""}
                  </div>
                </div>

                <div style={{
                  width: 70, height: 4, background: "var(--surface-sunk)", flexShrink: 0,
                  borderRadius: 2, overflow: "hidden",
                }}>
                  <div style={{
                    width: `${(d.count / max) * 100}%`, height: "100%",
                    background: color,
                  }} />
                </div>
                <span style={{
                  fontWeight: 600, color: "var(--text-soft)",
                  fontVariantNumeric: "tabular-nums",
                  width: 28, textAlign: "right",
                }}>
                  {d.count}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}