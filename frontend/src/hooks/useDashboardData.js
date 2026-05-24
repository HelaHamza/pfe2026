import { useState, useCallback, useEffect } from 'react'
import { dashboardService } from '../services/api' // adjust path

export const useDashboardData = () => {
  const [state, setState] = useState({
    stats: null,
    timeline: [],
    byTactic: [],
    results: [],
    detectionSource: null,
    logsBySource: {},
    attacksBySource: {},
    sigmaBySource: {},
    sigmaByLevel: {},
    anomaliesBySource: {},
    lastReport: null,
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const fetchAll = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const dash = await dashboardService.getDashboard()
      setState({
        stats:             dash.stats,
        timeline:          dash.timeline || [],
        byTactic:          dash.by_tactic || [],
        results:           dash.results || [],
        detectionSource:   dash.detection_source,
        logsBySource:      dash.logs_by_source || {},
        attacksBySource:   dash.attacks_by_source || {},
        sigmaBySource:     dash.sigma_by_source || {},
        sigmaByLevel:      dash.sigma_by_level || {},
        anomaliesBySource: dash.anomalies_by_source || {},
        lastReport:        dash.report && !dash.report.error ? dash.report : null,
      })
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAll()
  }, [fetchAll])

  // 🆕 flatten everything to the top level so the component can destructure directly
  return { ...state, loading, error, fetchAll, setError }
}