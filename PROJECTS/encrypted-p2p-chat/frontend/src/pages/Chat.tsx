// ===================
// © AngelaMos | 2025
// Chat.tsx
// ===================
import { createSignal, Show, onMount, onCleanup } from "solid-js"
import type { JSX } from "solid-js"
import type { Participant } from "../types"
import { useStore } from "@nanostores/solid"
import { AppShell, ProtectedRoute } from "../components/Layout"
import {
  MessageList,
  ChatHeader,
  ChatInput,
  NewConversation,
} from "../components/Chat"
import {
  $activeRoom,
  $activeRoomId,
  $userId,
  showToast,
  addRoom,
  setActiveRoom,
} from "../stores"
import { api } from "../lib/api-client"
import {
  connectWebSocket,
  disconnectWebSocket,
  wsManager,
} from "../websocket"

export default function Chat(): JSX.Element {
  const activeRoom = useStore($activeRoom)
  const activeRoomId = useStore($activeRoomId)
  const userId = useStore($userId)
  const [showNewChat, setShowNewChat] = createSignal(false)

  onMount(() => {
    if (userId()) {
      connectWebSocket()
    }
  })

  onCleanup(() => {
    disconnectWebSocket()
  })

  const handleSendMessage = (content: string): void => {
    const roomId = activeRoomId()
    const room = activeRoom()

    if (roomId === null || room === null) return

    const recipientId = room.participants.find((p: Participant) => p.user_id !== userId())?.user_id

    if (recipientId === undefined) {
      showToast("error", "SEND FAILED", "NO RECIPIENT FOUND")
      return
    }

    wsManager.sendEncryptedMessage(
      recipientId,
      roomId,
      content
    )
  }

  const handleCreateRoom = async (targetUserId: string): Promise<void> => {
    try {
      const room = await api.rooms.create({
        participant_id: targetUserId,
        room_type: "direct",
      })

      addRoom(room)
      setActiveRoom(room.id)
      setShowNewChat(false)
    } catch {
      showToast("error", "FAILED", "COULD NOT CREATE CONVERSATION")
    }
  }

  const handleNewChat = (): void => {
    setShowNewChat(true)
  }

  return (
    <ProtectedRoute>
      <AppShell>
        <div class="h-full flex flex-col bg-black">
          <Show
            when={activeRoomId()}
            fallback={<EmptyState onNewChat={handleNewChat} />}
            keyed
          >
            {(roomId) => (
              <>
                <ChatHeader
                  room={activeRoom()}
                />
                <MessageList
                  roomId={roomId}
                />
                <ChatInput
                  roomId={roomId}
                  recipientId={activeRoom()?.participants.find((p: Participant) => p.user_id !== userId())?.user_id ?? ""}
                  onSend={handleSendMessage}
                />
              </>
            )}
          </Show>
        </div>

        <NewConversation
          isOpen={showNewChat()}
          onClose={() => setShowNewChat(false)}
          onCreateRoom={handleCreateRoom}
        />
      </AppShell>
    </ProtectedRoute>
  )
}

interface EmptyStateProps {
  onNewChat: () => void
}

function EmptyState(props: EmptyStateProps): JSX.Element {
  return (
    <div class="h-full flex flex-col items-center justify-center p-4">
      <div class="text-center">
        <ChatIcon />
        <h2 class="font-pixel text-sm text-orange mt-4 mb-2">
          SELECT A CONVERSATION
        </h2>
        <p class="font-pixel text-[10px] text-gray mb-6">
          CHOOSE A CHAT FROM THE SIDEBAR OR START A NEW ONE
        </p>
        <button
          type="button"
          onClick={() => props.onNewChat()}
          class="px-6 py-3 border-2 border-orange text-orange font-pixel text-[10px] hover:bg-orange hover:text-black transition-colors"
        >
          START NEW CHAT
        </button>
      </div>
    </div>
  )
}

function ChatIcon(): JSX.Element {
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" class="text-orange mx-auto">
      <rect x="8" y="8" width="32" height="4" />
      <rect x="4" y="12" width="4" height="24" />
      <rect x="40" y="12" width="4" height="24" />
      <rect x="8" y="36" width="12" height="4" />
      <rect x="28" y="36" width="12" height="4" />
      <rect x="20" y="40" width="4" height="4" />
      <rect x="16" y="44" width="4" height="4" />
      <rect x="12" y="18" width="24" height="2" />
      <rect x="12" y="24" width="16" height="2" />
      <rect x="12" y="30" width="20" height="2" />
    </svg>
  )
}
