// ===================
// © AngelaMos | 2025
// crypto-service.ts
// ===================
import type {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  DoubleRatchetState,
  EncryptedMessage,
} from "../types"
import { DEFAULT_ONE_TIME_PREKEY_COUNT } from "../types"
import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  initiateX3DH,
  receiveX3DH,
} from "./x3dh"
import {
  initializeRatchetSender,
  initializeRatchetReceiver,
  encryptMessage,
  decryptMessage,
  serializeRatchetState,
  deserializeRatchetState,
} from "./double-ratchet"
import {
  saveIdentityKey,
  getIdentityKey,
  saveSignedPreKey,
  getLatestSignedPreKey,
  saveOneTimePreKeys,
  getUnusedOneTimePreKeys,
  getOneTimePreKey,
  markOneTimePreKeyUsed,
  saveRatchetState,
  getRatchetState,
  deleteRatchetState,
  clearAllKeys,
} from "./key-store"
import { api } from "../lib/api-client"
import {
  base64ToBytes,
  bytesToBase64,
  generateX25519KeyPair,
} from "./primitives"

class CryptoService {
  private userId: string | null = null
  private identityKeyPair: IdentityKeyPair | null = null
  private signedPreKey: SignedPreKey | null = null
  private ratchetStates = new Map<string, DoubleRatchetState>()
  private initialized = false

  async initialize(userId: string): Promise<void> {
    if (this.initialized && this.userId === userId) return

    this.userId = userId
    this.ratchetStates.clear()

    this.identityKeyPair = await getIdentityKey(userId)

    if (this.identityKeyPair === null) {
      await this.generateAndStoreKeys()
    }

    this.signedPreKey = await getLatestSignedPreKey(userId)

    if (this.signedPreKey === null || this.isSignedPreKeyExpired(this.signedPreKey)) {
      await this.rotateSignedPreKey()
    }

    const unusedOTPs = await getUnusedOneTimePreKeys(userId)
    if (unusedOTPs.length < DEFAULT_ONE_TIME_PREKEY_COUNT / 2) {
      await this.replenishOneTimePreKeys()
    }

    this.initialized = true
  }

  private isSignedPreKeyExpired(preKey: SignedPreKey): boolean {
    return new Date(preKey.expires_at) < new Date()
  }

  private async generateAndStoreKeys(): Promise<void> {
    if (!this.userId) throw new Error("User ID not set")

    this.identityKeyPair = await generateIdentityKeyPair()
    await saveIdentityKey(this.userId, this.identityKeyPair)

    this.signedPreKey = await generateSignedPreKey(this.identityKeyPair.ed25519_private)
    await saveSignedPreKey(this.userId, this.signedPreKey)

    const oneTimePreKeys = await generateOneTimePreKeys(DEFAULT_ONE_TIME_PREKEY_COUNT)
    await saveOneTimePreKeys(this.userId, oneTimePreKeys)

    await this.uploadPublicKeys(oneTimePreKeys)
  }

  private async rotateSignedPreKey(): Promise<void> {
    if (this.userId === null || this.identityKeyPair === null) throw new Error("Not initialized")

    this.signedPreKey = await generateSignedPreKey(this.identityKeyPair.ed25519_private)
    await saveSignedPreKey(this.userId, this.signedPreKey)

    await api.encryption.rotateSignedPrekey(this.userId)
  }

  private async replenishOneTimePreKeys(): Promise<void> {
    if (!this.userId) throw new Error("User ID not set")

    const newPreKeys = await generateOneTimePreKeys(DEFAULT_ONE_TIME_PREKEY_COUNT / 2)
    await saveOneTimePreKeys(this.userId, newPreKeys)
  }

  private async uploadPublicKeys(_oneTimePreKeys: OneTimePreKey[]): Promise<void> {
    if (!this.userId) throw new Error("User ID not set")
    await api.encryption.initializeKeys(this.userId)
  }

  async establishSession(peerId: string): Promise<void> {
    if (this.identityKeyPair === null) throw new Error("Identity keys not initialized")

    const existingState = await this.getRatchetState(peerId)
    if (existingState !== null) return

    const peerBundle = await api.encryption.getPrekeyBundle(peerId)

    const x3dhResult = await initiateX3DH(this.identityKeyPair, peerBundle)

    const peerIdentityKey = base64ToBytes(peerBundle.identity_key)

    const ratchetState = await initializeRatchetSender(
      peerId,
      x3dhResult.shared_key,
      peerIdentityKey
    )

    this.ratchetStates.set(peerId, ratchetState)

    const serialized = await serializeRatchetState(ratchetState)
    await saveRatchetState(serialized)
  }

  async handleIncomingSession(
    peerId: string,
    senderIdentityKey: string,
    ephemeralKey: string,
    oneTimePreKeyId: string | null
  ): Promise<void> {
    if (this.identityKeyPair === null || this.signedPreKey === null) {
      throw new Error("Keys not initialized")
    }

    let oneTimePreKey: OneTimePreKey | null = null
    if (oneTimePreKeyId !== null) {
      oneTimePreKey = await getOneTimePreKey(oneTimePreKeyId)
      if (oneTimePreKey !== null) {
        await markOneTimePreKeyUsed(oneTimePreKeyId)
      }
    }

    const sharedKey = await receiveX3DH(
      this.identityKeyPair,
      this.signedPreKey,
      oneTimePreKey,
      senderIdentityKey,
      ephemeralKey
    )

    const dhKeyPair = await generateX25519KeyPair()

    const ratchetState = await initializeRatchetReceiver(
      peerId,
      sharedKey,
      dhKeyPair
    )

    this.ratchetStates.set(peerId, ratchetState)

    const serialized = await serializeRatchetState(ratchetState)
    await saveRatchetState(serialized)
  }

  async encrypt(peerId: string, plaintext: string): Promise<{
    ciphertext: string
    nonce: string
    header: string
  }> {
    const state = await this.getRatchetState(peerId)
    if (state === null) {
      await this.establishSession(peerId)
      return await this.encrypt(peerId, plaintext)
    }

    const plaintextBytes = new TextEncoder().encode(plaintext)
    const encrypted = await encryptMessage(state, plaintextBytes)

    const serialized = await serializeRatchetState(state)
    await saveRatchetState(serialized)

    return {
      ciphertext: bytesToBase64(encrypted.ciphertext),
      nonce: bytesToBase64(encrypted.nonce),
      header: JSON.stringify(encrypted.header),
    }
  }

  async decrypt(
    peerId: string,
    ciphertext: string,
    nonce: string,
    header: string
  ): Promise<string> {
    let state = await this.getRatchetState(peerId)

    const parsedHeader = JSON.parse(header) as EncryptedMessage["header"]
    const encryptedMessage: EncryptedMessage = {
      ciphertext: base64ToBytes(ciphertext),
      nonce: base64ToBytes(nonce),
      header: parsedHeader,
    }

    if (state === null) {
      await this.handleIncomingSession(
        peerId,
        parsedHeader.dh_public_key,
        parsedHeader.dh_public_key,
        null
      )
      state = await this.getRatchetState(peerId)
    }

    if (state === null) {
      throw new Error("Failed to establish session")
    }

    const plaintextBytes = await decryptMessage(state, encryptedMessage)

    const serialized = await serializeRatchetState(state)
    await saveRatchetState(serialized)

    return new TextDecoder().decode(plaintextBytes)
  }

  private async getRatchetState(peerId: string): Promise<DoubleRatchetState | null> {
    let state = this.ratchetStates.get(peerId)

    if (state === undefined) {
      const serialized = await getRatchetState(peerId)
      if (serialized !== null && serialized !== undefined) {
        state = await deserializeRatchetState(serialized)
        this.ratchetStates.set(peerId, state)
      }
    }

    return state ?? null
  }

  async endSession(peerId: string): Promise<void> {
    this.ratchetStates.delete(peerId)
    await deleteRatchetState(peerId)
  }

  async clearAllSessions(): Promise<void> {
    this.ratchetStates.clear()
    await clearAllKeys()
    this.initialized = false
  }

  getPublicIdentityKey(): string | null {
    return this.identityKeyPair?.x25519_public ?? null
  }

  isInitialized(): boolean {
    return this.initialized
  }
}

export const cryptoService = new CryptoService()
