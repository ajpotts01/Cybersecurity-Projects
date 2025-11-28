/**
 * Main application shell with sidebar and content area
 */

import type { ParentProps, JSX } from "solid-js"
import { Show } from "solid-js"
import { useStore } from "@nanostores/solid"
import { $sidebarOpen, $isMobile } from "../../stores"
import { Sidebar } from "./Sidebar"
import { Header } from "./Header"

interface AppShellProps extends ParentProps {
  showSidebar?: boolean
  showHeader?: boolean
}

export function AppShell(props: AppShellProps): JSX.Element {
  const sidebarOpen = useStore($sidebarOpen)
  const isMobile = useStore($isMobile)

  const showSidebar = (): boolean => props.showSidebar ?? true
  const showHeader = (): boolean => props.showHeader ?? true

  const getSidebarClasses = (): string => {
    if (isMobile()) {
      return sidebarOpen() ? "fixed inset-y-0 left-0 z-40 w-72" : "hidden"
    }
    return sidebarOpen() ? "w-72" : "w-0 overflow-hidden"
  }

  const handleBackdropClick = (): void => {
    $sidebarOpen.set(false)
  }

  const handleBackdropKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " " || e.key === "Escape") {
      e.preventDefault()
      $sidebarOpen.set(false)
    }
  }

  return (
    <div class="h-screen flex flex-col bg-black overflow-hidden">
      <Show when={showHeader()}>
        <Header />
      </Show>

      <div class="flex-1 flex overflow-hidden">
        <Show when={showSidebar()}>
          <aside
            class={`
              flex-shrink-0 h-full
              border-r-2 border-orange
              transition-all duration-100
              ${getSidebarClasses()}
            `}
          >
            <Sidebar />
          </aside>

          <Show when={isMobile() && sidebarOpen()}>
            <div
              class="fixed inset-0 z-30 bg-black/80"
              role="button"
              tabIndex={0}
              onClick={handleBackdropClick}
              onKeyDown={handleBackdropKeyDown}
              aria-label="Close sidebar"
            />
          </Show>
        </Show>

        <main class="flex-1 overflow-hidden bg-black">
          {props.children}
        </main>
      </div>
    </div>
  )
}
