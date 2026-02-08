// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import {
  useDashboardOverview,
  useSeverityBreakdown,
  useTimeline,
  useTopSources,
} from '@/api/hooks'
import { EventTimeline } from './components/event-timeline'
import { SeverityChart } from './components/severity-chart'
import { StatCards } from './components/stat-cards'
import { TopSources } from './components/top-sources'
import styles from './dashboard.module.scss'

export function Component(): React.ReactElement {
  const overview = useDashboardOverview()
  const timeline = useTimeline()
  const severity = useSeverityBreakdown()
  const topSources = useTopSources()

  return (
    <div className={styles.page}>
      <StatCards data={overview.data} isLoading={overview.isLoading} />
      <EventTimeline data={timeline.data} isLoading={timeline.isLoading} />
      <div className={styles.row}>
        <SeverityChart data={severity.data} isLoading={severity.isLoading} />
        <TopSources data={topSources.data} isLoading={topSources.isLoading} />
      </div>
    </div>
  )
}

Component.displayName = 'Dashboard'
