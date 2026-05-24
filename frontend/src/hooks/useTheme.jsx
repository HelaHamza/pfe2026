import { useEffect, useState } from 'react'

/* Gère le thème clair/sombre. Applique data-theme sur le conteneur racine
   du dashboard (pas besoin de toucher au <html> global du reste de l'app). */
export function useTheme(defaultTheme = 'light') {
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return defaultTheme
    return window.localStorage.getItem('ai-dash-theme') || defaultTheme
  })

  useEffect(() => {
    try { window.localStorage.setItem('ai-dash-theme', theme) } catch { /* ignore */ }
  }, [theme])

  const toggle = () => setTheme((t) => (t === 'light' ? 'dark' : 'light'))
  return { theme, toggle, setTheme }
}

export function ThemeToggle({ theme, onToggle }) {
  return (
    <button className="theme-toggle" onClick={onToggle} type="button"
      aria-label={`Basculer en thème ${theme === 'light' ? 'sombre' : 'clair'}`}>
      <span className="theme-toggle__track" data-theme={theme}>
        <span className="theme-toggle__thumb">{theme === 'light' ? '☀' : '☾'}</span>
      </span>
    </button>
  )
}