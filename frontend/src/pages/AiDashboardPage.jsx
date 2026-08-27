import {
  useFrozenModel, useOverview, useRetraining,
  useTriage, useEvalComparison,
} from '../hooks/useAiDashboardData'
import { useTheme, ThemeToggle } from '../hooks/useTheme'
import Sidebar from '../components/Sidebar'
import DomainCard from '../components/ai-dashboard/DomainCard'
import FrozenModelSection from '../components/ai-dashboard/FrozenModelSection'
import AnalysisSection from '../components/ai-dashboard/AnalysisSection'
import EvalComparisonSection from '../components/ai-dashboard/EvalComparisonSection'
import RetrainingSection from '../components/ai-dashboard/RetrainingSection'

import '../styles/tokens.css'
import '../styles/ai-dashboard.css'

export default function AiDashboardPage() {
  const { theme, toggle } = useTheme('light')

  const frozen         = useFrozenModel()
  const overview       = useOverview()
  const triage         = useTriage()
  const evalComparison = useEvalComparison()
  const retraining     = useRetraining()

  return (
    <div className="ai-dash dash-theme" data-theme={theme}>
      <Sidebar />
      <main className="ai-dash__main">
        <header className="ai-dash__header">
          <div>
            <h1 className="ai-dash__title">Dashboard Expert IA</h1>
            <p className="ai-dash__subtitle">
              Santé et efficacité du système de détection
            </p>
          </div>
          <ThemeToggle theme={theme} onToggle={toggle} />
        </header>

        {/* ① Modèle en production : identité + calibration par source */}
        <DomainCard
          title="Modèle en production"
          hint="version déployée et calibration"
          loading={frozen.loading}
          error={frozen.error}
          hasData={frozen.data?.has_data}
          reason={frozen.data?.reason}
        >
          {frozen.data && <FrozenModelSection data={frozen.data} />}
        </DomainCard>

        {/* ③ Priorisation du dernier run : le LLM explique et priorise,
            il ne filtre plus. Répartition de sévérité + fail-open. */}
        <DomainCard
          title="Analyse des alertes"
          hint="dernière analyse — priorisation"
          loading={overview.loading}
          error={overview.error}
          hasData={overview.data?.has_data}
          reason={overview.data?.errors?.[0]}
        >
          {overview.data && (
            <AnalysisSection overview={overview.data} triage={triage.data} />
          )}
        </DomainCard>

        {/* ④ Capacité de détection : CNN seul vs CNN → LLM (attaques injectées).
            Panneau d'évaluation hors-bande — inchangé. */}
        <DomainCard
          title="Capacité de détection"
          hint="évaluation · vérité terrain"
          loading={evalComparison.loading}
          error={evalComparison.error}
          hasData={evalComparison.data?.has_data}
          reason={evalComparison.data?.reason}
        >
          {evalComparison.data && (
            <EvalComparisonSection data={evalComparison.data} />
          )}
        </DomainCard>

        {/* ② Contrôle qualité des mises à jour (ré-entraînement) */}
        <DomainCard
          title="Contrôle qualité des mises à jour"
          hint="validation avant mise en production"
          loading={retraining.loading}
          error={retraining.error}
          hasData={retraining.data?.has_data}
          reason={retraining.data?.reason}
        >
          {retraining.data && <RetrainingSection data={retraining.data} />}
        </DomainCard>

        {/* Carte « Alertes en attente de vérification » SUPPRIMÉE :
            plus d'épisodes incertains à revoir en mode explication seule. */}
      </main>
    </div>
  )
}