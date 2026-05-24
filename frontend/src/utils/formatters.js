export function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function timeAgo(iso) {
  if (!iso) return ''
  const diff = Math.round((Date.now() - new Date(iso)) / 60000)
  if (diff < 1)    return "à l'instant"
  if (diff < 60)   return `il y a ${diff} min`
  if (diff < 1440) return `il y a ${Math.floor(diff / 60)}h`
  return `il y a ${Math.floor(diff / 1440)}j`
}

export function formatDuration(start, end) {
  if (!start || !end) return '—'
  const s = Math.round((new Date(end) - new Date(start)) / 1000)
  if (s < 60)   return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}