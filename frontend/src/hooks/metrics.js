/* =============================================================================
   metrics.js — Calculs dérivés à partir de la réponse /compare ou /overview.
   Tout est calculé côté front à partir des matrices de confusion (cm) déjà
   présentes dans le payload : aucun changement back-end requis.
   ============================================================================= */

/** Matthews Correlation Coefficient — métrique robuste sur données déséquilibrées. */
export function mcc({ tp = 0, tn = 0, fp = 0, fn = 0 } = {}) {
  const num = tp * tn - fp * fn;
  const den = Math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
  if (den === 0) return null;
  return num / den;
}

/** Taux de faux positifs = FP / (FP + TN). LA métrique opérationnelle SOC. */
export function fpr({ fp = 0, tn = 0 } = {}) {
  const den = fp + tn;
  return den === 0 ? null : fp / den;
}

/** Recall macro = moyenne non pondérée des recalls par type d'attaque. */
export function macroRecall(attackResult = {}) {
  const vals = Object.values(attackResult)
    .map((a) => a?.recall)
    .filter((v) => typeof v === 'number');
  if (!vals.length) return null;
  return vals.reduce((s, v) => s + v, 0) / vals.length;
}

/** Pire attaque (min recall) — le maillon faible du modèle. */
export function worstAttack(attackResult = {}) {
  let worst = null;
  for (const [name, a] of Object.entries(attackResult)) {
    if (typeof a?.recall !== 'number') continue;
    if (!worst || a.recall < worst.recall) worst = { name, ...a };
  }
  return worst;
}

/** Formatage compact de nombres. */
export function fmt(v, digits = 4) {
  if (v == null || Number.isNaN(v)) return '—';
  if (typeof v !== 'number') return String(v);
  if (Number.isInteger(v)) return v.toLocaleString('fr-FR');
  return v.toFixed(digits);
}

export function fmtPct(v, digits = 1) {
  if (v == null || Number.isNaN(v)) return '—';
  return `${(v * 100).toFixed(digits)} %`;
}

export function fmtDelta(v, digits = 4) {
  if (v == null) return '';
  const s = v > 0 ? '+' : '';
  return `${s}${v.toFixed(digits)}`;
}

const PRETTY_ATTACK = {
  brute_force_ssh: 'Brute-force SSH',
  credential_access: 'Credential access',
  cryptominer: 'Cryptominer',
  lateral_movement: 'Lateral movement',
  log_tampering: 'Log tampering',
  privilege_escalation: 'Privilege escalation',
  reverse_shell: 'Reverse shell',
  ssh_key_implant: 'SSH key implant',
};
export const prettyAttack = (k) =>
  PRETTY_ATTACK[k] || k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

/**
 * Construit le "résumé exécutif" pour la dernière version d'une comparaison.
 * Accepte le payload /compare. Renvoie les KPI clés + un verdict.
 */
export function buildSummary(comparison) {
  if (!comparison || !comparison.versions?.length) return null;

  const versions = comparison.versions;
  const latest = versions[versions.length - 1];
  const prev = versions.length >= 2 ? versions[versions.length - 2] : null;

  // global metrics : tableau de lignes {version, precision:{value,delta}, ...}
  const gmRow = comparison.global_metrics?.find((r) => r.version === latest) || {};
  const gmPrev = prev ? comparison.global_metrics?.find((r) => r.version === prev) : null;

  // model_info porte tp/tn/fp/fn globaux
  const mi = comparison.model_info?.find((m) => m.version === latest) || {};
  const miPrev = prev ? comparison.model_info?.find((m) => m.version === prev) : null;

  const cmLatest = {
    tp: mi.global_tp, tn: mi.global_tn, fp: mi.global_fp, fn: mi.global_fn,
  };
  const cmPrev = miPrev
    ? { tp: miPrev.global_tp, tn: miPrev.global_tn, fp: miPrev.global_fp, fn: miPrev.global_fn }
    : null;

  const mccLatest = mcc(cmLatest);
  const mccPrev = cmPrev ? mcc(cmPrev) : null;
  const fprLatest = fpr(cmLatest);

  // recall par attaque : reconstruit depuis by_attack pour la version courante
  const attackResult = {};
  for (const [atk, series] of Object.entries(comparison.by_attack || {})) {
    const point = series.find((p) => p.version === latest);
    if (point) attackResult[atk] = { recall: point.value, detected: point.detected, total: point.total };
  }
  const macro = macroRecall(attackResult);
  const macroPrevObj = {};
  if (prev) {
    for (const [atk, series] of Object.entries(comparison.by_attack || {})) {
      const point = series.find((p) => p.version === prev);
      if (point) macroPrevObj[atk] = { recall: point.value };
    }
  }
  const macroPrev = prev ? macroRecall(macroPrevObj) : null;
  const worst = worstAttack(attackResult);

  return {
    latest,
    prev,
    mcc: { value: mccLatest, delta: mccPrev != null && mccLatest != null ? mccLatest - mccPrev : null },
    fpr: { value: fprLatest },
    macroRecall: { value: macro, delta: macroPrev != null && macro != null ? macro - macroPrev : null },
    worstAttack: worst,
    fp: { value: cmLatest.fp, prev: cmPrev?.fp },
    globalRecall: gmRow.recall || null,
    globalRecallPrev: gmPrev?.recall || null,
  };
}