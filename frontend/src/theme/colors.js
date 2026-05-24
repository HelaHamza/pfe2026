// ─────────────────────────────────────────────────────────────────────────────
// src/theme/colors.js
// Palette centralisée pour éviter la dérive de couleurs entre composants.
// Inspiré des conventions SOC (Splunk, Elastic SIEM, Wazuh).
// ─────────────────────────────────────────────────────────────────────────────

export const severity = {
  CRITICAL: { text: "#791F1F", bg: "#FCEBEB", bgStrong: "#A32D2D", border: "#F7C1C1" },
  HIGH:     { text: "#993C1D", bg: "#FAECE7", bgStrong: "#D85A30", border: "#F5C4B3" },
  MEDIUM:   { text: "#854F0B", bg: "#FAEEDA", bgStrong: "#BA7517", border: "#FAC775" },
  LOW:      { text: "#3B6D11", bg: "#EAF3DE", bgStrong: "#639922", border: "#C0DD97" },
};

export const detection = {
  ae_only:    "#378ADD",
  sigma_only: "#7F77DD",
  both:       "#1D9E75",
};

export const source = {
  // pour les barres "logs ingérés"
  logs:    "#378ADD",
  alerts:  "#A32D2D",
};

export const status = {
  ok:      "#1D9E75",
  warning: "#BA7517",
  error:   "#A32D2D",
  info:    "#185FA5",
};

export const neutral = {
  text:       "#0f172a",
  textMuted:  "#64748b",
  textFaint:  "#94a3b8",
  textGhost:  "#cbd5e1",
  bg:         "#ffffff",
  bgAlt:      "#f8fafc",
  bgMuted:    "#f1f5f9",
  border:     "#e2e8f0",
  borderSoft: "#f1f5f9",
};

// MITRE tactics — couleurs catégoriques cohérentes
export const mitre = [
  "#D85A30", // Impact (coral)
  "#534AB7", // Initial Access (purple)
  "#1D9E75", // Credential Access (teal)
  "#BA7517", // Persistence (amber)
  "#378ADD", // Reconnaissance (blue)
  "#D4537E", // Defense Evasion (pink)
  "#888780", // Command & Control (gray)
  "#639922", // Discovery (green)
];

// Helper : récupère la couleur d'une sévérité (case-insensitive, fallback gris)
export function sevColor(level) {
  const k = (level || "").toUpperCase();
  return severity[k] || { text: neutral.textMuted, bg: neutral.bgMuted, bgStrong: neutral.textMuted, border: neutral.border };
}