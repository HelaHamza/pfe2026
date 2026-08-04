import {
  useFrozenModel, useOverview, useRetraining,
  useTriage, useEvalComparison, usePending,
} from '../hooks/useAiDashboardData'
import { useTheme, ThemeToggle } from '../hooks/useTheme'
import Sidebar from '../components/Sidebar'
import DomainCard from '../components/ai-dashboard/DomainCard'
import FrozenModelSection from '../components/ai-dashboard/FrozenModelSection'
import AnalysisSection from '../components/ai-dashboard/AnalysisSection'
import EvalComparisonSection from '../components/ai-dashboard/EvalComparisonSection'
import RetrainingSection from '../components/ai-dashboard/RetrainingSection'
import PendingSection from '../components/ai-dashboard/PendingSection'

import '../styles/tokens.css'
import '../styles/ai-dashboard.css'

export default function AiDashboardPage() {
  const { theme, toggle } = useTheme('light')

  const frozen         = useFrozenModel()
  const overview       = useOverview()
  const triage         = useTriage()
  const evalComparison = useEvalComparison()
  const retraining     = useRetraining()
  const pending        = usePending()

  return (
    <div className="ai-dash" data-theme={theme}>
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

        {/* ③ Efficacité live (entonnoir CNN → LLM) + qualité triage */}
        <DomainCard
          title="Analyse des alertes"
          hint="dernière analyse"
          loading={overview.loading}
          error={overview.error}
          hasData={overview.data?.has_data}
          reason={overview.data?.errors?.[0]}
        >
          {overview.data && (
            <AnalysisSection overview={overview.data} triage={triage.data} />
          )}
        </DomainCard>

        {/* ④ Capacité de détection : CNN seul vs CNN → LLM (attaques injectées) */}
        <DomainCard
          title="Capacité de détection"
          hint="CNN seul vs CNN → LLM"
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

        {/* Alertes en attente de vérification */}
        <DomainCard
          title="Alertes en attente de vérification"
          hint="Cas incertains du dernier analyse"
          loading={pending.loading}
          error={pending.error}
          hasData={(pending.data?.results?.length ?? 0) > 0}
          reason="Aucun épisode en attente de revue."
        >
          {pending.data && <PendingSection data={pending.data} />}
        </DomainCard>
      </main>
    </div>
  )
}