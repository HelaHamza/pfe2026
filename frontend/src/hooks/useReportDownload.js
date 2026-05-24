import { useCallback } from 'react'
import { buildReport, downloadJson } from '../utils/reportBuilder'

export function useReportDownload(data) {
  return useCallback(() => {
    if (!data.stats) return
    const report = buildReport(data)
    const filename = `ids_report_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`
    downloadJson(filename, report)
  }, [data])
}