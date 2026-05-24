import api from './api'

/**
 * Ouvre un stream SSE authentifié via fetch (EventSource ne supporte pas
 * les headers custom donc on ne peut pas y mettre le Bearer token).
 * Retourne une fonction de fermeture, équivalent à evtSource.close().
 */
export function openAuthenticatedStream(path, { onMessage, onError, onOpen } = {}) {
  const controller = new AbortController()
  const token = localStorage.getItem('token')

  fetch(`${api.defaults.baseURL}${path}`, {
    headers: {
      'Authorization': token ? `Bearer ${token}` : '',
      'Accept': 'text/event-stream',
    },
    signal: controller.signal,
  })
    .then(async (response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      onOpen?.()

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const blocks = buffer.split('\n\n')
        buffer = blocks.pop() || ''

        for (const block of blocks) {
          const dataLine = block.split('\n').find(l => l.startsWith('data: '))
          if (dataLine) onMessage?.({ data: dataLine.slice(6) })
        }
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') onError?.(err)
    })

  return () => controller.abort()
}