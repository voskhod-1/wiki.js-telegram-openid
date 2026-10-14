import crypto from 'crypto'

/* global WIKI */

const REQUEST_TIMEOUT_MS = 15000

export default class TelegramAuthentication {
  strategyId: string
  conf: Record<string, any>
  module?: string

  constructor(strategyId: string, conf: Record<string, any>) {
    this.strategyId = strategyId
    this.conf = conf
  }

  private settings(): { clientId: string; clientSecret: string; callbackURL: string; apiBase: string } {
    const clientId = String(this.conf.clientId || '').trim()
    const clientSecret = String(this.conf.clientSecret || '')
    const callbackURL = String(this.conf.callbackURL || '').trim()
    if (!clientId || !clientSecret) {
      WIKI.logger.warn(`Telegram strategy ${this.strategyId} is not configured: Client ID and Client Secret are required.`)
      throw new Error('ERR_STRATEGY_MISCONFIGURED')
    }
    if (!callbackURL) {
      WIKI.logger.warn(`Telegram strategy ${this.strategyId} is not configured: a Callback URL is required.`)
      throw new Error('ERR_STRATEGY_MISCONFIGURED')
    }
    return { clientId, clientSecret, callbackURL, apiBase: this.apiBase }
  }

  private get apiBase(): string {
    const custom = String(this.conf.customApiUrl || '').trim()
    if (!custom) {
      WIKI.logger.info('[Telegram] No custom API URL provided. Using default Telegram servers.')
      return 'https://oauth.telegram.org'
    }
    let parsed: URL
    try {
      parsed = new URL(custom)
    } catch (err: any) {
      WIKI.logger.error(`[Telegram] Invalid customApiUrl provided: "${custom}". Falling back to default.`)
      WIKI.logger.error(`[Telegram] Error:`, err.message)
      return 'https://oauth.telegram.org'
    }
    const prefix = parsed.pathname.replace(/\/$/, '')
    WIKI.logger.info(`[Telegram] Custom API URL is ACTIVE: ${custom}`)
    WIKI.logger.info(`[Telegram] Proxy Host: ${parsed.hostname}, Prefix: ${prefix}`)
    return `https://${parsed.hostname}${prefix}`
  }

  private async reach(url: string, init: RequestInit = {}): Promise<Response> {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
    } catch (err: any) {
      WIKI.logger.warn(`[Telegram] could not reach ${url}: ${err.message}`)
      throw new Error('ERR_PROVIDER_REQUEST_FAILED')
    }
  }

  async authorizationUrl({ redirectUri, state, codeChallenge }: any): Promise<string> {
    const { clientId, apiBase } = this.settings()

    const authParams: Record<string, string> = {
      client_id: clientId,
      redirect_uri: String(redirectUri || ''),
      response_type: 'code',
      scope: 'openid profile',
      state: String(state || '')
    }

    if (codeChallenge) {
      authParams.code_challenge = String(codeChallenge)
      authParams.code_challenge_method = 'S256'
    }

    const redirectURL = `${apiBase}/auth?` + new URLSearchParams(authParams).toString()
    WIKI.logger.info(`[Telegram] Redirecting to: ${redirectURL}`)
    return redirectURL
  }

  async profile({ code, redirectUri, codeVerifier }: any): Promise<any> {
    const { clientId, clientSecret, callbackURL, apiBase } = this.settings()

    if (!code) {
      throw new Error('ERR_NO_AUTHORIZATION_CODE')
    }

    const tokenURL = `${apiBase}/token`

    const postData = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: String(redirectUri || callbackURL),
      ...(codeVerifier ? { code_verifier: String(codeVerifier) } : {})
    }).toString()

    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64')

    WIKI.logger.info(`[Telegram] HTTP POST to: ${tokenURL}`)

    const tokenResp = await this.reach(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': String(Buffer.byteLength(postData)),
        Authorization: `Basic ${basicAuth}`,
        Accept: 'application/json',
        'User-Agent': 'Wiki.js'
      },
      body: postData
    })

    let body = ''
    try {
      body = await tokenResp.text()
    } catch {
      throw new Error('ERR_TOKEN_EXCHANGE_FAILED')
    }

    if (!tokenResp.ok) {
      WIKI.logger.error(`[Telegram] HTTP Error: ${tokenResp.status}`)
      try {
        const errorData = JSON.parse(body)
        throw new Error(
          `Telegram API error (${tokenResp.status}): ${
            errorData.error_description || errorData.error || 'Unknown error'
          }`
        )
      } catch (e: any) {
        if (e.message?.startsWith('Telegram API error')) throw e
        throw new Error(`HTTP ${tokenResp.status}: ${body}`)
      }
    }

    let tokenData: Record<string, any>
    try {
      tokenData = JSON.parse(body)
    } catch {
      WIKI.logger.error(`[Telegram] Failed to parse response: ${body}`)
      throw new Error('ERR_TOKEN_EXCHANGE_FAILED')
    }

    if (!tokenData.id_token) {
      throw new Error('No ID token received')
    }

    const payload = decodeJWT(tokenData.id_token)
    if (!payload) {
      throw new Error('Failed to decode ID token')
    }

    // --- Защита от undefined на всех уровнях ---
    const rawId = payload.sub || payload.id
    const rawUsername = payload.preferred_username
    const rawName = payload.name
    const rawPicture = payload.picture

    if (!rawId) {
      throw new Error('Telegram account ID is missing from the ID token')
    }
    if (!rawUsername || !String(rawUsername).trim()) {
      throw new Error('Telegram account must have a username')
    }

    const telegramId = String(rawId)
    const username = String(rawUsername).trim()
    const name = rawName && String(rawName).trim() ? String(rawName).trim() : username
    const picture = rawPicture && String(rawPicture).trim() ? String(rawPicture).trim() : ''

    // toLowerCase получает гарантированно строку
    const cleanIdentifier = username.toLowerCase().replace(/[^a-z0-9_]/g, '_')
    const generatedEmail = `${cleanIdentifier}@telegram.org`

    // Проверка, что email — не undefined и не пустая строка
    if (!generatedEmail || typeof generatedEmail !== 'string') {
      throw new Error('Failed to generate a valid email address')
    }

    // Используйте это:
    const profile = {
      id: String(telegramId),
      email: generatedEmail,
      displayName: name || username || 'Telegram User', // ✅ строка
      picture: picture || '',
      provider: 'telegram'
    }
    
    WIKI.logger.info(`[Telegram] Profile: ${profile.username} <${generatedEmail}>`)

    return profile
  }
}

function decodeJWT(token: string): Record<string, any> | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null

    const payload = parts[1]
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/')
    const jsonString = Buffer.from(base64, 'base64').toString('utf8')

    return JSON.parse(jsonString)
  } catch (err: any) {
    WIKI.logger.error(`[Telegram] JWT decode error:`, err.message)
    return null
  }
}
