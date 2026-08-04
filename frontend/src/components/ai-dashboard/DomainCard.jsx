/* Socle commun des cartes du dashboard IA.
   3 états universels : chargement, erreur, vide. En cas de vide, on affiche
   le `reason` du backend (POURQUOI c'est vide) au lieu d'un message muet. */
export default function DomainCard({
  title, hint, loading, error, hasData, reason, children,
}) {
  return (
    <section className="card">
      <div className="card__head">
        <h2 className="card__title">{title}</h2>
        {hint && <span className="card__hint">{hint}</span>}
      </div>

      {loading && <div className="ai-dash__state">Chargement…</div>}
      {error && <div className="ai-dash__error">Erreur : {error}</div>}
      {!loading && !error && !hasData && (
        <div className="ai-dash__empty">
          {reason || 'Aucune donnée pour cette section.'}
        </div>
      )}
      {!loading && !error && hasData && children}
    </section>
  )
}