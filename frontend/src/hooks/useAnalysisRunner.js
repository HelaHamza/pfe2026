import { useState, useCallback, useRef } from 'react'
import { dashboardService } from '../services/api'
import { openAuthenticatedStream } from '../services/streamClient'

const STEPS = [
  'Analyse depuis', 'Nouveaux logs', 'Lancement AE',
  '[AE]', '[SIGMA]', 'Corrélation', '[FUSION]',
  'Curseur mis à jour', 'Résultats', 'terminée',
]
const MAX_RETRIES = 3

export function useAnalysisRunner({ onComplete, onError } = {}) {
  const [analysing, setAnalysing] = useState(false)
  const [logs, setLogs] = useState([])
  const [pct, setPct] = useState(0)
  const closeRef = useRef(null)

  const launch = useCallback(async () => {
    if (analysing) return
    try {
      const resp = await dashboardService.launchAnalysis()
      if (resp.status === 'already_running') return

      setAnalysing(true); setLogs([]); setPct(0)
      let retries = 0
      let stepCount = 0

      closeRef.current = openAuthenticatedStream('/run/analyse/stream', {
        onMessage: (e) => {
          try {
            const data = JSON.parse(e.data)
            if (data.msg === '__DONE__') {
              closeRef.current?.()
              setPct(100)
              setTimeout(() => {
                setAnalysing(false); setLogs([]); setPct(0)
                onComplete?.()
              }, 1200)
              return
            }
            setLogs(prev => [...prev.slice(-6), data.msg])
            const matched = STEPS.findIndex(s => data.msg.includes(s))
            if (matched >= stepCount) {
              stepCount = matched + 1
              setPct(Math.min(Math.round((stepCount / STEPS.length) * 95), 95))
            }
          } catch {}
        },
        onError: () => {
          retries++
          if (retries >= MAX_RETRIES) {
            closeRef.current?.()
            setAnalysing(false); setPct(0)
            onError?.('Connexion au stream perdue — l\'analyse tourne peut-être encore en arrière-plan')
            onComplete?.()
          }
        },
      })
    } catch (e) {
      setAnalysing(false)
      onError?.(e.message)
    }
  }, [analysing, onComplete, onError])

  return { analysing, logs, pct, launch }
}