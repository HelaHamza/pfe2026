import { useState } from 'react'

import { useDashboardData }  from '../hooks/useDashboardData'
import { useAnalysisRunner } from '../hooks/useAnalysisRunner'
import { useReportDownload } from '../hooks/useReportDownload'

import TopBar                from '../components/dashboard/Topbar'
import KpiBand               from '../components/dashboard/Kpiband'
import MitreTopTactics       from '../components/dashboard/MitreTopTactics'
import SigmaSeverityBars     from '../components/dashboard/SigmaSeverityBars'
import LogSourceActivity     from '../components/dashboard/LogSourceActivity'
import CnnVerdictBreakdown   from '../components/dashboard/CnnVerdictBreakdown'
import SecurityTable         from '../components/dashboard/Securitytable'
import DetailPanel           from '../components/dashboard/Detailpanel'
import LastAnalysisModal     from '../components/dashboard/modals/LastAnalysisModal'
import AnalysisProgress      from '../components/dashboard/modals/AnalysisProgress'
import ErrorBanner           from '../components/dashboard/layout/ErrorBanner'
import EmptyDashboardState   from '../components/dashboard/layout/EmptySOCDashboardState'
import Sidebar from '../components/Sidebar'
import { neutral } from '../theme/colors'

export default function DashboardPage() {
  const [selected,  setSelected]  = useState(null)
  const [showModal, setShowModal] = useState(false)

  const data = useDashboardData()
  const {
    stats, error, loading, fetchAll, setError,
    hasData, status, errors, lastStartedAt, lastFinishedAt, runId,
    logsBySource, anomaliesBySource, sigmaByLevel, cnnByVerdict, byTactic, results,
  } = data

  const { analysing, logs, pct, launch } = useAnalysisRunner({
    onComplete: fetchAll,
    onError:    setError,
  })

  const downloadReport = useReportDownload(data)

  // « Dernier run » reconstruit depuis le contrat (plus de dash.report).
  const lastReport = hasData ? {
    started_at:  lastStartedAt,
    finished_at: lastFinishedAt,
    status,
    analysis_id: runId,
    stats,
  } : null

  const isEmpty = !loading && !analysing && !hasData

  const pipelineIssue = (status === 'partial' || status === 'failed')
                     && (errors?.length > 0)

  // Message explicatif quand le tableau est vide : on distingue « aucune
  // détection » de « tout écarté par le LLM » pour ne pas laisser croire à un bug.
  const emptyHint = results.length > 0 ? null : (() => {
    const raw = stats?.cnn_episodes ?? 0   // anomalies AE brutes (avant triage)
    const sig = stats?.sigma_alerts ?? 0
    if (raw === 0 && sig === 0)
      return "Aucune anomalie AE ni alerte Sigma détectée sur ce run."
    const parts = []
    if (raw > 0) parts.push(`${raw} anomalie(s) AE, toutes écartées par le LLM (faux positifs / incertains)`)
    if (sig === 0) parts.push("aucune alerte Sigma")
    return `Rien à escalader vers le SOC — ${parts.join(' · ')}.`
  })()

  return (
  <div style={{
    minHeight: '100vh',
    background: neutral.bg,
    fontFamily: "'Inter','Segoe UI',system-ui,sans-serif",
    color: neutral.text,
    display: 'flex',
  }}>
    <Sidebar />

    <div style={{ flex: 1, minWidth: 0, overflowX: 'hidden' }}>

      {analysing && <AnalysisProgress pct={pct} logs={logs} />}

      {showModal && lastReport && (
        <LastAnalysisModal
          report={lastReport}
          stats={stats}
          onClose={() => setShowModal(false)}
          onLaunchNew={launch}
        />
      )}

      <TopBar
        onRefresh={fetchAll}
        loading={loading}
        analysing={analysing}
        onShowLastReport={() => setShowModal(true)}
        onLaunchNew={launch}
        onDownloadReport={downloadReport}
        lastReport={lastReport}
        statsReady={!!stats}
      />

      <ErrorBanner message={error} />
      {pipelineIssue && (
        <ErrorBanner
          message={errors.join(' · ')}
          variant={status === 'failed' ? 'error' : 'warning'}
        />
      )}

      <main style={{ maxWidth: 1400, margin: '0 auto', padding: '0 24px 40px' }}>
        {isEmpty ? (
          <EmptyDashboardState onLaunch={launch} />
        ) : (
          <>
            <KpiBand stats={stats} />

            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 12, marginBottom: 12 }}>
              <SigmaSeverityBars byLevel={sigmaByLevel} />
              <LogSourceActivity
                logsBySource={logsBySource}
                anomaliesBySource={anomaliesBySource}
                stats={stats}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 12, marginBottom: 12 }}>
              <MitreTopTactics data={byTactic} />
              <CnnVerdictBreakdown byVerdict={cnnByVerdict} />
            </div>

            <SecurityTable
              results={results}
              onSelect={setSelected}
              selected={selected}
              emptyHint={emptyHint}
            />
          </>
        )}
      </main>
    </div>

    {selected && <DetailPanel item={selected} onClose={() => setSelected(null)} />}
  </div>
)}