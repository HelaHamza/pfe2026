import { createContext, useContext, useEffect, useState } from 'react'

// Thème clair/sombre UNIQUE pour toute l'app (Home, auth, dashboards...).
// Clé localStorage inchangée (`ai-dash-theme`, historique) pour ne pas perdre
// la préférence déjà enregistrée par les utilisateurs du dashboard.
// Appliqué sur <html> (data-theme) : index.css et tokens.css (.dash-theme)
// lisent tous les deux cet attribut, chacun dans son propre scope.
const STORAGE_KEY = 'ai-dash-theme'

const ThemeContext = createContext(null)

export function ThemeProvider({ children, defaultTheme = 'light' }) {
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return defaultTheme
    return window.localStorage.getItem(STORAGE_KEY) || defaultTheme
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { window.localStorage.setItem(STORAGE_KEY, theme) } catch { /* ignore */ }
  }, [theme])

  const toggle = () => setTheme((t) => (t === 'light' ? 'dark' : 'light'))

  return (
    <ThemeContext.Provider value={{ theme, toggle, setTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return useContext(ThemeContext)
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
