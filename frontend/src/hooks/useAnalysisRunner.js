import { useState, useCallback, useRef } from 'react'
import { dashboardService } from '../services/api'

// Le backend n'a PAS de SSE : /analyse/run (lance) + /analyse/status (état).
// On lance, puis on POLL le statut. get_state() renvoie :
//   { running, done, error, run_id, started_at, finished_at, logs:[{ts,msg}] }
// Ce hook tolère aussi un état ENVELOPPÉ ({ state:{...} }) ou aplati.

const POLL_MS = 1500
const MAX_CONSECUTIVE_ERRORS = 8   // ~12 s d'échecs d'affilée → on abandonne le modal

const STEPS = [
  'Inférence CNN', 'épisodes CNN persistés',
  'Analyse Sigma', 'alertes Sigma persistées',
  'Curseur', 'Résumé de triage', 'Gate', 'éval', 'terminée',
]

// Déballe l'état quelle que soit la forme exacte renvoyée par la vue.
function unwrap(raw) {
  if (!raw || typeof raw !== 'object') return {}
  if (raw.state && typeof raw.state === 'object') return raw.state
  if (raw.data && typeof raw.data === 'object' && ('running' in raw.data || 'done' in raw.data)) return raw.data
  return raw
}

export function useAnalysisRunner({ onComplete, onError } = {}) {
  const [analysing, setAnalysing] = useState(false)
  const [logs, setLogs] = useState([])
  const [pct, setPct] = useState(0)
  const timerRef = useRef(null)
  const errRef = useRef(0)

  const stopPolling = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const finish = useCallback((errMsg) => {
    stopPolling()
    setPct(100)
    if (errMsg) onError?.(errMsg)
    setTimeout(() => {
      setAnalysing(false); setLogs([]); setPct(0)
      onComplete?.()      // recharge le dashboard (fetchAll)
    }, 900)
  }, [stopPolling, onComplete, onError])

  const launch = useCallback(async () => {
    if (analysing) return
    try {
      const resp = await dashboardService.launchAnalysis()   // POST /analyse/run
      if (resp?.status === 'already_running') return

      setAnalysing(true); setLogs([]); setPct(0)
      errRef.current = 0

      timerRef.current = setInterval(async () => {
        let state
        try {
          state = unwrap(await dashboardService.getAnalysisStatus())  // GET /analyse/status
          errRef.current = 0
        } catch (e) {
          errRef.current += 1
          if (errRef.current >= MAX_CONSECUTIVE_ERRORS) {
            finish("Statut d'analyse illisible — la page va se rafraîchir.")
          }
          return
        }

        // Logs : [{ts,msg}] ou [string]. On garde les 7 derniers.
        const msgs = (state.logs || []).map(l => (typeof l === 'string' ? l : l?.msg)).filter(Boolean)
        setLogs(msgs.slice(-7))

        // Progression approximative depuis les jalons franchis.
        const step = STEPS.filter(s => msgs.some(m => m.includes(s))).length
        setPct(prev => Math.max(prev, Math.min(Math.round((step / STEPS.length) * 95), 95)))

        // FIN : done=true OU running repassé à false. Robuste aux deux conventions.
        const isDone = state.done === true || state.running === false
        if (isDone) {
          finish(state.error || null)
        }
      }, POLL_MS)
    } catch (e) {
      stopPolling()
      setAnalysing(false)
      onError?.(e.message)
    }
  }, [analysing, finish, stopPolling, onError])

  return { analysing, logs, pct, launch }
}