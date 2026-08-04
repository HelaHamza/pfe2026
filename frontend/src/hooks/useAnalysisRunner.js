import { useState, useCallback, useRef } from 'react'
import { dashboardService } from '../services/api'

// Le backend n'expose PAS de stream SSE : il a /analyse/run (lance) et
// /analyse/status (état + logs). On lance, puis on POLL le statut.
//
// get_state() renvoie : { running, done, error, run_id, started_at,
//                         finished_at, logs: [{ts, msg}, ...] }

const POLL_MS = 1500

// Étapes attendues → progression approximative (le backend ne renvoie pas de %).
const STEPS = [
  'Inférence CNN', 'épisodes CNN persistés',
  'Règles Sigma', 'alertes Sigma persistées',
  'Curseur', 'Résumé de triage', 'Gate', 'éval', 'terminée',
]

export function useAnalysisRunner({ onComplete, onError } = {}) {
  const [analysing, setAnalysing] = useState(false)
  const [logs, setLogs] = useState([])
  const [pct, setPct] = useState(0)
  const timerRef = useRef(null)

  const stopPolling = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const launch = useCallback(async () => {
    if (analysing) return
    try {
      const resp = await dashboardService.launchAnalysis()   // POST /analyse/run
      if (resp?.status === 'already_running') return

      setAnalysing(true); setLogs([]); setPct(0)

      timerRef.current = setInterval(async () => {
        let state
        try {
          state = await dashboardService.getAnalysisStatus()  // GET /analyse/status
        } catch (e) {
          // Erreur réseau ponctuelle : on retente au prochain tick.
          return
        }

        // Logs : liste de { ts, msg } → on garde les 7 derniers messages.
        const msgs = (state.logs || []).map(l => (typeof l === 'string' ? l : l.msg))
        setLogs(msgs.slice(-7))

        // Progression approximative depuis les jalons franchis.
        const done = STEPS.filter(s => msgs.some(m => m.includes(s))).length
        setPct(prev => Math.max(prev, Math.min(Math.round((done / STEPS.length) * 95), 95)))

        // Fin de run.
        if (state.done || state.running === false) {
          stopPolling()
          setPct(100)
          if (state.error) onError?.(state.error)
          setTimeout(() => {
            setAnalysing(false); setLogs([]); setPct(0)
            onComplete?.()        // recharge le dashboard (fetchAll)
          }, 1000)
        }
      }, POLL_MS)
    } catch (e) {
      stopPolling()
      setAnalysing(false)
      onError?.(e.message)
    }
  }, [analysing, onComplete, onError, stopPolling])

  return { analysing, logs, pct, launch }
}