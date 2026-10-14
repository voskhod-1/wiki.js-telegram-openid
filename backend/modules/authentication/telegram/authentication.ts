import crypto from 'crypto'

/* global WIKI */

/**
 * Telegram
 *
 * Wiki.js 3.0.0-beta calls these modules as classes: the engine constructs one with
 * `(strategyId, conf)` and then asks it for `authorizationUrl()` on the way out and `profile()` on
 * the way back. There is no passport, no `passport.use()` and no `init()` — the registration is
 * done by the core from `definition.yml`.
 *
 * The OAuth logic below is the same as the old passport-based module:
 *
 *   - a custom API URL replaces the Telegram host and keeps its path as a prefix, so a proxy
 *     mounted under a subpath answers the same routes;
 *   - PKCE is used, with the verifier kept in the session by the flow;
 *   - the token is exchanged over `application/x-www-form-urlencoded` with the client credentials in
 *     HTTP Basic auth, which is what the old `postJSON` did;
 *   - the `id_token` is decoded without verifying its signature — it was just fetched over TLS from
 *     the token endpoint that signed it, so there is no second party to check against;
 *   - a username is required, and the email is derived from it as `<username>@telegram.org`.
 */

/**
 * How long a request to the token endpoint may take before it is treated as unreachable.
 */
const REQUEST_TIMEOUT_MS = 15000

export default class TelegramAuthentication {
  strategyId: string
  conf: Record<string, any>
  /** Set by `models/authentication.ts` right after construction. */
  module?: string

  constructor(strategyId: string, conf: Record<string, any>) {
    this.strategyId = strategyId
    this.conf = conf
  }

  /**
   * The strategy's settings, refused if they cannot describe a login.
   *
   * @throws `ERR_STRATEGY_MISCONFIGURED`
   */
  private settings(): { clientId: string; clientSecret: string; callbackURL: string; apiBase: string } {
    const clientId = (this.conf.clientId || '').trim()
    const clientSecret = this.conf.clientSecret || ''
    const callbackURL = (this.conf.callbackURL || '').trim()
    if (!clientId || !clientSecret) {
      WIKI.logger.warn(
        `Telegram strategy ${this.strategyId} is not configured: Client ID and Client Secret are required.`
      )
      throw new Error('ERR_STRATEGY_MISCONFIGURED')
    }
    if (!callbackURL) {
      WIKI.logger.warn(
        `Telegram strategy ${this.strategyId} is not configured: a Callback URL is required.`
      )
      throw new Error('ERR_STRATEGY_MISCONFIGURED')
    }
    return { clientId, clientSecret, callbackURL, apiBase: this.apiBase }
  }

  /**
   * Where Telegram's OAuth endpoints live.
   *
   * A custom URL keeps its path as a prefix, so a proxy mounted under a subpath answers at the same
   * routes Telegram does. An empty value falls back to Telegram's own servers, exactly as before.
   * A value that cannot be parsed is a misconfiguration and is reported as one.
   */
  private get apiBase(): string {
    const custom = (this.conf.customApiUrl || '').trim()
    if (!custom) {
      WIKI.logger.info('[Telegram] ℹ️ No custom API URL provided. Using default Telegram servers.')
      return 'https://oauth.telegram.org'
    }

    let parsed: URL
    try {
      parsed = new URL(custom)
    } catch (err: any) {
      WIKI.logger.error(
        `[Telegram] ❌ Invalid customApiUrl provided: "${custom}". Falling back to default.`
      )
      WIKI.logger.error(`[Telegram] Error:`, err.message)
      return 'https://oauth.telegram.org'
    }

    const prefix = parsed.pathname.replace(/\/$/, '')
    WIKI.logger.info(`[Telegram] ✅ Custom API URL is ACTIVE: ${custom}`)
    WIKI.logger.info(`[Telegram] Proxy Host: ${parsed.hostname}, Prefix: ${prefix}`)
    return `https://${parsed.hostname}${prefix}`
  }

  /**
   * `fetch`, with an unreachable provider reported as a provider failure rather than as itself.
   *
   * A rejected fetch carries a message about sockets and DNS, and the callback route puts whatever
   * it caught into the URL it redirects to — so left alone, "fetch failed" is what the person
   * trying to log in reads.
   */
  private async reach(url: string, init: RequestInit = {}): Promise<Response> {
    try {
      return await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
      })
    } catch (err: any) {
      WIKI.logger.warn(`[Telegram] could not reach ${url}: ${err.message}`)
      throw new Error('ERR_PROVIDER_REQUEST_FAILED')
    }
  }

  async authorizationUrl({ redirectUri, state, codeChallenge }: any): Promise<string> {
    const { clientId, apiBase } = this.settings()

    // The redirect_uri is taken from the flow, not from the configured callback URL: the flow is
    // the one that knows the scheme and host the browser actually reached this installation on.
    const authURL = `${apiBase}/auth`

    const authParams: Record<string, string> = {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid profile',
      state
    }

    // PKCE, exactly as the old module built it — a 32-byte base64url verifier and its S256 challenge.
    if (codeChallenge) {
      authParams.code_challenge = codeChallenge
      authParams.code_challenge_method = 'S256'
    }

    const redirectURL = `${authURL}?` + new URLSearchParams(authParams).toString()
    WIKI.logger.info(`[Telegram] Redirecting to: ${redirectURL}`)
    return redirectURL
  }

  async profile({ code, redirectUri, codeVerifier }: any): Promise<any> {
    const { clientId, clientSecret, callbackURL, apiBase } = this.settings()

    if (!code) {
      throw new Error('ERR_NO_AUTHORIZATION_CODE')
    }

    const tokenURL = `${apiBase}/token`

    // The old module sent this as x-www-form-urlencoded with Basic auth. Telegram accepts both, so
    // the wire format is kept.
    const postData = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: redirectUri || callbackURL,
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

    const telegramId = payload.sub || payload.id
    const username = payload.preferred_username
    const name = payload.name
    const picture = payload.picture

    if (!username || !String(username).trim()) {
      throw new Error('Telegram account must have a username')
    }

    const cleanIdentifier = String(username).toLowerCase().replace(/[^a-z0-9_]/g, '_')
    const generatedEmail = `${cleanIdentifier}@telegram.org`

    // The shape the old module handed to `processProfile` is preserved: id, username, displayName,
    // a name object, emails[], photos[], provider.
    const profile = {
      id: String(telegramId),
      username,
      displayName: name || username,
      name: { givenName: name || username },
      emails: [{ value: generatedEmail, primary: true }],
      photos: picture ? [{ value: picture }] : [],
      provider: 'telegram'
    }

    WIKI.logger.info(`[Telegram] Profile: ${profile.username} <${generatedEmail}>`)

    return profile
  }
}

/**
 * The claims inside an ID token, without verifying its signature.
 *
 * The token was just fetched over TLS from the token endpoint itself, which is the party that signed
 * it, so there is no second party to check against — the same reasoning the old module was written
 * with.
 */
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
