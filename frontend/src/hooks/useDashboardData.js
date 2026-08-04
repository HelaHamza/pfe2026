import { useState, useCallback, useEffect } from 'react'
import { dashboardService } from '../services/api' // adjust path

// État vide aligné sur le contrat backend actuel :
//   /dashboard  → haut de page (KPIs, charts, bannière, état vide)
//   /results    → lignes de la table (ResultsResponse : { total, results:[...] })
const EMPTY = {
  hasData: false,
  status: null,            // "completed" | "partial" | "failed" | null
  errors: [],
  lastStartedAt: null,
  lastFinishedAt: null,
  stats: null,
  byTactic: [],
  cnnBySeverity: {},
  cnnByVerdict: {},
  sigmaByLevel: {},
  logsBySource: {},
  results: [],
  resultsTotal: 0,
  runId: null,
}

export const useDashboardData = () => {
  const [state, setState] = useState(EMPTY)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const fetchAll = useCallback(async () => {
    setLoading(true); setError('')
    try {
      // Deux sources distinctes → une seule passe réseau.
      const [dash, resultsResp] = await Promise.all([
        dashboardService.getDashboard(),
        dashboardService.getResults(),
      ])
      setState({
        hasData:        dash.has_data,
        status:         dash.status,
        errors:         dash.errors || [],
        lastStartedAt:  dash.last_started_at,
        lastFinishedAt: dash.last_finished_at,
        stats:          dash.stats,
        byTactic:       dash.by_tactic || [],
        cnnBySeverity:  dash.cnn_by_severity || {},
        cnnByVerdict:   dash.cnn_by_verdict || {},
        sigmaByLevel:   dash.sigma_by_level || {},
        logsBySource:   dash.logs_by_source || {},
        // ResultsResponse : les lignes sont dans .results, PAS la réponse nue.
        results:        resultsResp.results || [],
        resultsTotal:   resultsResp.total ?? 0,
        runId:          resultsResp.run_id ?? null,
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

  // flatten au top-level : les composants destructurent directement.
  return { ...state, loading, error, fetchAll, setError }
}