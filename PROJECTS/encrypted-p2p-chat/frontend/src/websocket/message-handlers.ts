// ===================
// © AngelaMos | 2025
// message-handlers.ts
// ===================
import type {
  WSMessage,
  EncryptedMessageWS,
  TypingIndicatorWS,
  PresenceUpdateWS,
  ReadReceiptWS,
  ErrorMessageWS,
  Message,
} from "../types"
import {
  isEncryptedMessageWS,
  isTypingIndicatorWS,
  isPresenceUpdateWS,
  isReadReceiptWS,
  isErrorMessageWS,
} from "../types/guards"
import {
  addMessage,
  updateMessageStatus,
} from "../stores/messages.store"
import {
  setUserPresence,
} from "../stores/presence.store"
import {
  setUserTyping,
} from "../stores/typing.store"
import { showToast } from "../stores/ui.store"

type MessageHandler<T extends WSMessage> = (message: T) => void

const encryptedMessageHandler: MessageHandler<EncryptedMessageWS> = (message) => {
  const chatMessage: Message = {
    id: message.message_id,
    room_id: message.room_id,
    sender_id: message.sender_id,
    sender_username: message.sender_username,
    content: message.ciphertext,
    status: "delivered",
    is_encrypted: true,
    encrypted_content: message.ciphertext,
    nonce: message.nonce,
    header: message.header,
    created_at: message.timestamp ?? new Date().toISOString(),
    updated_at: message.timestamp ?? new Date().toISOString(),
  }

  addMessage(message.room_id, chatMessage)
}

const typingIndicatorHandler: MessageHandler<TypingIndicatorWS> = (message) => {
  setUserTyping(
    message.room_id,
    message.user_id,
    message.username,
    message.is_typing
  )
}

const presenceUpdateHandler: MessageHandler<PresenceUpdateWS> = (message) => {
  setUserPresence(
    message.user_id,
    message.status,
    message.last_seen
  )
}

const readReceiptHandler: MessageHandler<ReadReceiptWS> = (message) => {
  updateMessageStatus(message.room_id, message.message_id, "read")
}

const errorMessageHandler: MessageHandler<ErrorMessageWS> = (message) => {
  showToast("error", "CONNECTION ERROR", message.error_message.toUpperCase())
}

export function handleWSMessage(message: WSMessage): void {
  if (isEncryptedMessageWS(message)) {
    encryptedMessageHandler(message)
  } else if (isTypingIndicatorWS(message)) {
    typingIndicatorHandler(message)
  } else if (isPresenceUpdateWS(message)) {
    presenceUpdateHandler(message)
  } else if (isReadReceiptWS(message)) {
    readReceiptHandler(message)
  } else if (isErrorMessageWS(message)) {
    errorMessageHandler(message)
  }
}

export function handleEncryptedMessage(message: EncryptedMessageWS): void {
  encryptedMessageHandler(message)
}

export function handleTypingIndicator(message: TypingIndicatorWS): void {
  typingIndicatorHandler(message)
}

export function handlePresenceUpdate(message: PresenceUpdateWS): void {
  presenceUpdateHandler(message)
}

export function handleReadReceipt(message: ReadReceiptWS): void {
  readReceiptHandler(message)
}

export function handleErrorMessage(message: ErrorMessageWS): void {
  errorMessageHandler(message)
}
