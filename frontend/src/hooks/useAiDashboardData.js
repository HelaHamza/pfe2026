import { useState, useEffect, useCallback } from 'react'
import { aiDashboardService } from '../services/api'

// Usine : un hook de fetch générique, réutilisé par chaque section.
// loading / error / reload isolés par section — miroir du has_data backend.
function useDomain(fetcher) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await fetcher())
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Erreur de chargement')
    } finally {
      setLoading(false)
    }
  }, [fetcher])

  useEffect(() => { load() }, [load])
  return { data, loading, error, reload: load }
}

export const useFrozenModel    = () => useDomain(aiDashboardService.frozenModel)
export const useOverview       = () => useDomain(aiDashboardService.overview)
export const useRetraining     = () => useDomain(aiDashboardService.retraining)
export const useTriage         = () => useDomain(aiDashboardService.triage)
export const useEvalComparison = () => useDomain(aiDashboardService.evalComparison)
export const usePending        = () => useDomain(aiDashboardService.pending)