// ===================
// ©AngelaMos | 2026
// theme.ts
// ===================

import { buildChartTheme } from '@visx/xychart'

export const chartTheme = buildChartTheme({
  backgroundColor: 'transparent',
  colors: [
    'hsl(0, 84%, 39%)',
    'hsl(0, 72%, 60%)',
    'hsl(24, 95%, 63%)',
    'hsl(45, 93%, 57%)',
    'hsl(217, 91%, 70%)',
  ],
  gridColor: 'hsl(0, 0%, 18%)',
  gridColorDark: 'hsl(0, 0%, 11.1%)',
  svgLabelSmall: { fill: 'hsl(0, 0%, 53.7%)' },
  svgLabelBig: { fill: 'hsl(0, 0%, 70.6%)' },
  tickLength: 4,
})

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'hsl(0, 72%, 60%)',
  high: 'hsl(24, 95%, 63%)',
  medium: 'hsl(45, 93%, 57%)',
  low: 'hsl(217, 91%, 70%)',
  info: 'hsl(0, 0%, 53.7%)',
}

export const STATUS_COLORS: Record<string, string> = {
  new: 'hsl(217, 91%, 70%)',
  acknowledged: 'hsl(38, 92%, 60%)',
  investigating: 'hsl(263, 70%, 70%)',
  resolved: 'hsl(142, 76%, 46%)',
  false_positive: 'hsl(0, 0%, 53.7%)',
}
