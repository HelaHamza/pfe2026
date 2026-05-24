import { useState } from 'react'

import { useDashboardData }  from '../hooks/useDashboardData'
import { useAnalysisRunner } from '../hooks/useAnalysisRunner'
import { useReportDownload } from '../hooks/useReportDownload'

import TopBar                from '../components/dashboard/Topbar'
import KpiBand               from '../components/dashboard/Kpiband'
import MitreTopTactics       from '../components/dashboard/MitreTopTactics'
import SigmaSeverityBars     from '../components/dashboard/SigmaSeverityBars'
import LogSourceActivity     from '../components/dashboard/LogSourceActivity'
import SigmaBySeveritySource from '../components/dashboard/SigmaBySeveritySource'
import SecurityTable         from '../components/dashboard/Securitytable'
import DetailPanel           from '../components/dashboard/Detailpanel'
import LastAnalysisModal     from '../components/dashboard/modals/LastAnalysisModal'
import AnalysisProgress      from '../components/dashboard/modals/AnalysisProgress'
import ErrorBanner           from '../components/dashboard/layout/ErrorBanner'
import EmptyDashboardState   from '../components/dashboard/layout/EmptySOCDashboardState'  // 🆕
import Sidebar from '../components/Sidebar'
import { neutral } from '../theme/colors'

export default function DashboardPage() {
  const [selected,  setSelected]  = useState(null)
  const [showModal, setShowModal] = useState(false)

  const data = useDashboardData()
  const {
    stats, lastReport, error, loading, fetchAll, setError,
    logsBySource, attacksBySource, sigmaByLevel, sigmaBySource,
    anomaliesBySource, byTactic, results,
  } = data

  const { analysing, logs, pct, launch } = useAnalysisRunner({
    onComplete: fetchAll,
    onError:    setError,
  })

  const downloadReport = useReportDownload(data)

  // 🆕 Détection de l'état vide
  const isEmpty = !loading
               && !analysing
               && !stats?.ae_anomalies
               && !stats?.sigma_alerts
               && results.length === 0

  return (
  <div style={{
    minHeight: '100vh',
    background: neutral.bg,
    fontFamily: "'Inter','Segoe UI',system-ui,sans-serif",
    color: neutral.text,
    display: 'flex',           // 🆕 layout horizontal
  }}>
    <Sidebar />                {/* 🆕 sidebar à gauche */}

    {/* 🆕 wrapper pour le contenu principal */}
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

      <main style={{ maxWidth: 1400, margin: '0 auto', padding: '0 24px 40px' }}>
        {isEmpty ? (
          <EmptyDashboardState onLaunch={launch} />
        ) : (
          <>
            <KpiBand
              stats={stats}
              logsBySource={logsBySource}
              attacksBySource={attacksBySource}
            />

            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 12, marginBottom: 12 }}>
              <SigmaSeverityBars byLevel={sigmaByLevel} />
              <LogSourceActivity
                logsBySource={logsBySource}
                anomaliesBySource={anomaliesBySource}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 12, marginBottom: 12 }}>
              <MitreTopTactics data={byTactic} />
              <SigmaBySeveritySource bySource={sigmaBySource} />
            </div>

            <SecurityTable
              results={results}
              onSelect={setSelected}
              selected={selected}
            />
          </>
        )}
      </main>
    </div>

    {selected && <DetailPanel item={selected} onClose={() => setSelected(null)} />}
  </div>
)}