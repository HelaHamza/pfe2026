import { useState, useEffect, useCallback } from 'react'
import { aiDashboardService } from '../services/api'

export function useAiDashboardData() {
  const [comparison, setComparison] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      // compare() sans argument = toutes les versions, ordre chronologique
      const data = await aiDashboardService.compare()
      setComparison(data)
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Erreur de chargement')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return { comparison, loading, error, reload: load }
}