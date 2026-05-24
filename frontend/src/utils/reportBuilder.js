export function buildReport({
  stats, sigmaByLevel, sigmaBySource, logsBySource,
  attacksBySource, detectionSource, byTactic, lastReport,
}) {
  return {
    generated_at: new Date().toISOString(),
    cursor:       stats?.cursor || '—',
    kpis: {
      total_ae_anomalies: stats?.ae_anomalies    ?? 0,
      total_sigma_alerts: stats?.sigma_alerts    ?? 0,
      critical_alerts:    stats?.critical        ?? 0,
      correlated:         stats?.correlated_both ?? 0,
    },
    sigma_by_severity: sigmaByLevel,
    sigma_by_source:   sigmaBySource,
    logs_by_source:    logsBySource,
    attacks_by_source: attacksBySource,
    detection_repartition: {
      ae_only:    detectionSource?.ae_only    ?? 0,
      sigma_only: detectionSource?.sigma_only ?? 0,
      both:       detectionSource?.both       ?? 0,
    },
    top_mitre_tactics: byTactic,
    last_saved_analysis: lastReport ? {
      analysis_id: lastReport.analysis_id,
      finished_at: lastReport.finished_at,
      started_at:  lastReport.started_at,
    } : null,
  }
}

export function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}