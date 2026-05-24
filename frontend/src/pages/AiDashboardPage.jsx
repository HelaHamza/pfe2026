import { useMemo, useState } from 'react'
import { useAiDashboardData } from '../hooks/useAiDashboardData'
import { buildSummary } from '../hooks/metrics'
import { useTheme, ThemeToggle } from '../hooks/useTheme'
import Sidebar from '../components/Sidebar'

import SummaryBanner from '../components/ai-dashboard/SummaryBanner'
//import VersionSelector from '../components/ai-dashboard/VersionSelector'
import RecallByAttackChart from '../components/ai-dashboard/RecallByAttackChart'
import GlobalMetricsSection from '../components/ai-dashboard/GlobalMetricsSection'
import ModelConfigSection from '../components/ai-dashboard/ModelConfigSection'
import MetricsBySourceCards from '../components/ai-dashboard/MetricsBySourceCards'
import ConfusionMatrices from '../components/ai-dashboard/ConfusionMatrices'
import SeparationPanel from '../components/ai-dashboard/SeparationPanel'
import ThresholdsCleaningSection from '../components/ai-dashboard/ThresholdsCleaningSection'
import SingleVersionNotice from '../components/ai-dashboard/SingleVersionNotice'

import '../styles/tokens.css'
import '../styles/ai-dashboard.css'

function filterComparison(comparison, selected) {
  if (!comparison) return comparison
  const keep = (arr) => (arr || []).filter((x) => selected.includes(x.version))
  const keepSeries = (obj) => {
    const out = {}
    for (const [k, series] of Object.entries(obj || {})) {
      out[k] = series.filter((p) => selected.includes(p.version))
    }
    return out
  }
  return {
    ...comparison,
    versions: comparison.versions.filter((v) => selected.includes(v)),
    global_metrics: keep(comparison.global_metrics),
    hyperparameters: keep(comparison.hyperparameters),
    model_info: keep(comparison.model_info),
    robustness: keep(comparison.robustness),
    inference_timing: keep(comparison.inference_timing),
    separation: keep(comparison.separation),
    thresholds: keep(comparison.thresholds),
    cleaning: keep(comparison.cleaning),
    by_attack: keepSeries(comparison.by_attack),
    by_source: keepSeries(comparison.by_source),
  }
}

export default function AiDashboardPage() {
  const { comparison, loading, error } = useAiDashboardData()
  const { theme, toggle } = useTheme('light')
  const [selected, setSelected] = useState(null)

  const allVersions = comparison?.versions || []
  const effectiveSelected = selected || allVersions

  const view = useMemo(
    () => filterComparison(comparison, effectiveSelected),
    [comparison, effectiveSelected]
  )
  const summary = useMemo(() => buildSummary(view), [view])

  return (
    <div className="ai-dash" data-theme={theme}>
      <Sidebar />
      <main className="ai-dash__main">
        {loading && <div className="ai-dash__state">Chargement des métriques du modèle…</div>}
        {error && <div className="ai-dash__error">Erreur : {error}</div>}

        {view && (
          <>
            <header className="ai-dash__header">
              <div>
                <h1 className="ai-dash__title">Dashboard Expert IA</h1>
                <p className="ai-dash__subtitle">
                  Comparaison de modèles de détection d'intrusion · {allVersions.length} version(s)
                </p>
              </div>
              <ThemeToggle theme={theme} onToggle={toggle} />
            </header>
{/* 
            {allVersions.length >= 2 && (
              <VersionSelector versions={allVersions} selected={effectiveSelected} onChange={setSelected} />
            )} */}

            {!comparison.comparison_available && <SingleVersionNotice message={comparison.message} />}

            <SummaryBanner summary={summary} />

            <section className="card">
              <div className="card__head">
                <h2 className="card__title">Détection par type d'attaque</h2>
                <span className="card__hint">trié par rappel · seuil 50 %</span>
              </div>
              <RecallByAttackChart byAttack={view.by_attack} versions={view.versions} />
            </section>

            {/* ===== LIGNE 1 — Metriques globales ===== */}
            <section className="card">
              <div className="card__head">
                <h2 className="card__title">1 · Métriques globales du modèle</h2>
                <span className="card__hint">performance · vitesse · stabilité</span>
              </div>
              <GlobalMetricsSection
                globalMetrics={view.global_metrics}
                robustness={view.robustness}
                timing={view.inference_timing}
              />
            </section>

            {/* ===== LIGNE 2 — Parametres & hyperparametres ===== */}
            <section className="card">
              <div className="card__head">
                <h2 className="card__title">2 · Paramètres &amp; hyperparamètres</h2>
                <span className="card__hint">architecture &amp; configuration d'entraînement</span>
              </div>
              <ModelConfigSection modelInfo={view.model_info} hyperparameters={view.hyperparameters} />
            </section>

            {/* ===== LIGNE 3 — Metriques par source ===== */}
            <section className="card">
              <div className="card__head">
                <h2 className="card__title">3 · Métriques par source</h2>
                <span className="card__hint">auth · auditd · syslog</span>
              </div>
              <MetricsBySourceCards
                bySource={view.by_source}
                version={view.versions[view.versions.length - 1]}
              />
            </section>

            {/* ===== Section expert — Matrices de confusion ===== */}
            <section className="card">
              <div className="card__head">
                <h2 className="card__title">Matrices de confusion</h2>
                <span className="card__hint">global &amp; par source · TP / FP / FN / TN</span>
              </div>
              <ConfusionMatrices
                separation={view.separation}
                bySource={view.by_source}
                version={view.versions[view.versions.length - 1]}
              />
            </section>

            {/* ===== Section expert — Séparation autoencodeur ===== */}
            <section className="card">
              <div className="card__head">
                <h2 className="card__title">Séparation de reconstruction</h2>
                <span className="card__hint">qualité de l'autoencodeur · MSE normal vs attaque</span>
              </div>
              <SeparationPanel separation={view.separation} />
            </section>

            {/* ===== Section expert — Seuils & nettoyage ===== */}
            <section className="card">
              <div className="card__head">
                <h2 className="card__title">Seuils de décision &amp; nettoyage des données</h2>
                <span className="card__hint">décision par seuil · qualité du dataset</span>
              </div>
              <ThresholdsCleaningSection thresholds={view.thresholds} cleaning={view.cleaning} />
            </section>
          </>
        )}
      </main>
    </div>
  )
}