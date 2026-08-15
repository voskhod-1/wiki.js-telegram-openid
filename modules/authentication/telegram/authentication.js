/* global WIKI */

const crypto = require('crypto')
const https = require('https')
const url = require('url')

module.exports = {
  init(passport, conf) {
    WIKI.logger.info('[Telegram] Initializing strategy')
    WIKI.logger.info(`[Telegram] Config: clientID=${conf.clientId}, callbackURL=${conf.callbackURL}`)
    
    const issuerURL = 'https://oauth.telegram.org'
    const authURL = `${issuerURL}/auth`
    const tokenURL = `${issuerURL}/token`

    // Функция HTTP POST запроса с Basic Auth и подробным логированием
    function postJSON(endpoint, data, clientId, clientSecret) {
      return new Promise((resolve, reject) => {
        WIKI.logger.info(`[Telegram] HTTP POST to: ${endpoint}`)
        WIKI.logger.info(`[Telegram] POST data keys: ${Object.keys(data).join(', ')}`)
        WIKI.logger.info(`[Telegram] POST data:`, {
          ...data,
          code: data.code ? `${data.code.substring(0, 10)}...` : 'undefined',
          code_verifier: data.code_verifier ? `${data.code_verifier.substring(0, 10)}...` : 'undefined'
        })
        
        const postData = new url.URLSearchParams(data).toString()
        const parsedUrl = new URL(endpoint)
        
        // Создаем Basic Auth заголовок
        const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
        WIKI.logger.info(`[Telegram] Basic auth header created for clientID: ${clientId}`)
        
        const options = {
          hostname: parsedUrl.hostname,
          port: 443,
          path: parsedUrl.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData),
            'Authorization': `Basic ${basicAuth}`
          }
        }
        
        WIKI.logger.info(`[Telegram] Request options:`, {
          hostname: options.hostname,
          path: options.path,
          method: options.method,
          headers: {
            ...options.headers,
            'Authorization': 'Basic ***' // Не логируем сам токен
          }
        })
        
        const req = https.request(options, (res) => {
          WIKI.logger.info(`[Telegram] Response received - Status: ${res.statusCode}`)
          WIKI.logger.info(`[Telegram] Response headers:`, res.headers)
          
          let body = ''
          res.on('data', (chunk) => {
            body += chunk
            WIKI.logger.info(`[Telegram] Response chunk received: ${chunk.length} bytes`)
          })
          
          res.on('end', () => {
            WIKI.logger.info(`[Telegram] Response body (first 500 chars):`, body.substring(0, 500))
            
            // Проверяем HTTP статус
            if (res.statusCode !== 200) {
              WIKI.logger.error(`[Telegram] HTTP Error: ${res.statusCode}`)
              try {
                const errorData = JSON.parse(body)
                WIKI.logger.error(`[Telegram] Error response parsed:`, errorData)
                const errorMsg = errorData.error_description || errorData.error || 'Unknown error'
                reject(new Error(`Telegram API error (${res.statusCode}): ${errorMsg}`))
              } catch (e) {
                WIKI.logger.error(`[Telegram] Failed to parse error response:`, e.message)
                reject(new Error(`HTTP ${res.statusCode}: ${body}`))
              }
              return
            }
            
            try {
              const jsonData = JSON.parse(body)
              WIKI.logger.info(`[Telegram] Response JSON parsed successfully`)
              WIKI.logger.info(`[Telegram] Response keys: ${Object.keys(jsonData).join(', ')}`)
              if (jsonData.id_token) {
                WIKI.logger.info(`[Telegram] id_token received (length: ${jsonData.id_token.length})`)
              }
              if (jsonData.access_token) {
                WIKI.logger.info(`[Telegram] access_token received (length: ${jsonData.access_token.length})`)
              }
              resolve(jsonData)
            } catch (e) {
              WIKI.logger.error(`[Telegram] Failed to parse JSON response:`, e.message)
              WIKI.logger.error(`[Telegram] Raw response:`, body)
              reject(new Error(`Failed to parse response: ${body}`))
            }
          })
        })
        
        req.on('error', (err) => {
          WIKI.logger.error(`[Telegram] Request error:`, err.message)
          WIKI.logger.error(`[Telegram] Request error stack:`, err.stack)
          reject(err)
        })
        
        WIKI.logger.info(`[Telegram] Sending request body (${postData.length} bytes)...`)
        req.write(postData)
        WIKI.logger.info(`[Telegram] Request body sent, ending request...`)
        req.end()
        WIKI.logger.info(`[Telegram] Request completed, waiting for response...`)
      })
    }

    const TelegramStrategy = function(options, verify) {
      WIKI.logger.info(`[Telegram] Creating strategy instance`)
      this.name = options.name || 'telegram'
      this._verify = verify
      this._callbackURL = options.callbackURL
      this._clientID = options.clientID
      this._clientSecret = options.clientSecret
      this._scope = options.scope || ['openid', 'profile']
      
      WIKI.logger.info(`[Telegram] Strategy configured:`, {
        name: this.name,
        callbackURL: this._callbackURL,
        clientID: this._clientID,
        scope: this._scope
      })
    }

    TelegramStrategy.prototype.authenticate = async function(req, options) {
      const authStartTime = Date.now()
      WIKI.logger.info(`[Telegram] === authenticate() called ===`)
      WIKI.logger.info(`[Telegram] Request method: ${req.method}`)
      WIKI.logger.info(`[Telegram] Request URL: ${req.url}`)
      WIKI.logger.info(`[Telegram] Query params:`, req.query || {})
      WIKI.logger.info(`[Telegram] Session exists: ${!!req.session}`)
      
      try {
        const self = this
        
        // Если нет code - делаем редирект на авторизацию
        if (!req.query || !req.query.code) {
          WIKI.logger.info(`[Telegram] No code in query - initiating authorization flow`)
          
          const state = crypto.randomBytes(32).toString('hex')
          const codeVerifier = crypto.randomBytes(32).toString('base64url')
          const codeChallenge = crypto.createHash('sha256')
            .update(codeVerifier)
            .digest('base64url')
          
          WIKI.logger.info(`[Telegram] PKCE parameters generated:`)
          WIKI.logger.info(`[Telegram]   state: ${state.substring(0, 20)}... (${state.length} chars)`)
          WIKI.logger.info(`[Telegram]   code_verifier: ${codeVerifier.substring(0, 20)}... (${codeVerifier.length} chars)`)
          WIKI.logger.info(`[Telegram]   code_challenge: ${codeChallenge.substring(0, 20)}... (${codeChallenge.length} chars)`)
          
          // Инициализируем сессию если нужно
          if (!req.session) {
            WIKI.logger.warn(`[Telegram] Session not initialized, creating...`)
            req.session = {}
          }
          
          req.session.telegramState = state
          req.session.telegramCodeVerifier = codeVerifier
          req.session.telegramAuthStartTime = Date.now()
          
          WIKI.logger.info(`[Telegram] PKCE data saved to session`)
          WIKI.logger.info(`[Telegram] Session keys after save: ${Object.keys(req.session).join(', ')}`)
          
          const authParams = {
            client_id: this._clientID,
            redirect_uri: this._callbackURL,
            response_type: 'code',
            scope: this._scope.join(' '),
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
          }
          
          WIKI.logger.info(`[Telegram] Authorization URL parameters:`, authParams)
          
          const redirectURL = `${authURL}?` + new URLSearchParams(authParams).toString()
          
          WIKI.logger.info(`[Telegram] Full redirect URL: ${redirectURL}`)
          WIKI.logger.info(`[Telegram] Redirecting user to Telegram...`)
          
          return this.redirect(redirectURL)
        }
        
        // === CALLBACK PROCESSING ===
        WIKI.logger.info(`[Telegram] === Processing callback ===`)
        
        const code = req.query.code
        const state = req.query.state
        
        WIKI.logger.info(`[Telegram] Received parameters:`)
        WIKI.logger.info(`[Telegram]   code: ${code ? code.substring(0, 20) + '...' : 'undefined'} (${code ? code.length : 0} chars)`)
        WIKI.logger.info(`[Telegram]   state: ${state ? state.substring(0, 20) + '...' : 'undefined'} (${state ? state.length : 0} chars)`)
        
        // Проверяем сессию
        if (!req.session) {
          WIKI.logger.error('[Telegram] CRITICAL: Session is not available')
          WIKI.logger.error('[Telegram] Session object:', req.session)
          return this.fail('Session not available', 500)
        }
        
        WIKI.logger.info(`[Telegram] Session available, keys: ${Object.keys(req.session).join(', ')}`)
        
        const savedState = req.session.telegramState
        const codeVerifier = req.session.telegramCodeVerifier
        const authStartTimeSession = req.session.telegramAuthStartTime
        
        if (authStartTimeSession) {
          const elapsed = Date.now() - authStartTimeSession
          WIKI.logger.info(`[Telegram] Time since auth start: ${elapsed}ms`)
        }
        
        if (!savedState) {
          WIKI.logger.error('[Telegram] CRITICAL: savedState is missing in session')
          WIKI.logger.error('[Telegram] Session contents:', req.session)
          return this.fail('Invalid session state - savedState missing', 403)
        }
        
        if (!codeVerifier) {
          WIKI.logger.error('[Telegram] CRITICAL: codeVerifier is missing in session')
          WIKI.logger.error('[Telegram] Session contents:', req.session)
          return this.fail('Invalid session state - codeVerifier missing', 403)
        }
        
        WIKI.logger.info(`[Telegram] Retrieved from session:`)
        WIKI.logger.info(`[Telegram]   savedState: ${savedState.substring(0, 20)}... (${savedState.length} chars)`)
        WIKI.logger.info(`[Telegram]   codeVerifier: ${codeVerifier.substring(0, 20)}... (${codeVerifier.length} chars)`)
        
        if (state !== savedState) {
          WIKI.logger.error(`[Telegram] CRITICAL: State mismatch!`)
          WIKI.logger.error(`[Telegram]   Expected: ${savedState}`)
          WIKI.logger.error(`[Telegram]   Received: ${state}`)
          return this.fail('Invalid state parameter', 403)
        }
        
        WIKI.logger.info(`[Telegram] State validation passed`)
        WIKI.logger.info(`[Telegram] Preparing token exchange request...`)
        
        // Обмениваем code на токены
        const tokenData = await postJSON(tokenURL, {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: this._callbackURL,
          code_verifier: codeVerifier
        }, this._clientID, this._clientSecret)
        
        WIKI.logger.info(`[Telegram] Token exchange completed`)
        WIKI.logger.info(`[Telegram] Token response:`, {
          ...tokenData,
          id_token: tokenData.id_token ? `${tokenData.id_token.substring(0, 50)}...` : 'undefined',
          access_token: tokenData.access_token ? `${tokenData.access_token.substring(0, 50)}...` : 'undefined'
        })
        
        if (!tokenData.id_token) {
          WIKI.logger.error(`[Telegram] CRITICAL: No id_token in response`)
          WIKI.logger.error(`[Telegram] Full response:`, tokenData)
          return this.fail('No ID token received', 500)
        }
        
        WIKI.logger.info(`[Telegram] Decoding JWT id_token...`)
        const payload = decodeJWT(tokenData.id_token)
        
        if (!payload) {
          WIKI.logger.error(`[Telegram] CRITICAL: Failed to decode ID token`)
          return this.fail('Failed to decode ID token', 500)
        }
        
        WIKI.logger.info(`[Telegram] JWT decoded successfully`)
        WIKI.logger.info(`[Telegram] JWT payload:`, payload)
        WIKI.logger.info(`[Telegram] JWT payload keys: ${Object.keys(payload).join(', ')}`)
        
        const telegramId = payload.sub || payload.id
        const username = payload.preferred_username
        const name = payload.name
        const picture = payload.picture
        
        WIKI.logger.info(`[Telegram] Extracted user data:`)
        WIKI.logger.info(`[Telegram]   telegramId: ${telegramId}`)
        WIKI.logger.info(`[Telegram]   username: ${username}`)
        WIKI.logger.info(`[Telegram]   name: ${name}`)
        WIKI.logger.info(`[Telegram]   picture: ${picture ? 'present' : 'absent'}`)
        
        if (!username || !username.trim()) {
          WIKI.logger.error(`[Telegram] CRITICAL: Username is missing or empty`)
          WIKI.logger.error(`[Telegram] Full payload:`, payload)
          return this.fail('Telegram account must have a username', 400)
        }
        
        const cleanIdentifier = username.toLowerCase().replace(/[^a-z0-9_]/g, '_')
        const generatedEmail = `${cleanIdentifier}@telegram.org`
        
        WIKI.logger.info(`[Telegram] Generated email: ${generatedEmail}`)
        
        const profile = {
          id: String(telegramId),
          username: username,
          displayName: name || username,
          name: { givenName: name || username },
          emails: [{ value: generatedEmail, primary: true }],
          photos: picture ? [{ value: picture }] : [],
          provider: 'telegram'
        }
        
        WIKI.logger.info(`[Telegram] Profile object created:`, {
          ...profile,
          emails: ['[hidden]'],
          photos: profile.photos.length > 0 ? ['[hidden]'] : []
        })
        
        // Очищаем сессию до вызова verify
        WIKI.logger.info(`[Telegram] Cleaning up session...`)
        delete req.session.telegramState
        delete req.session.telegramCodeVerifier
        delete req.session.telegramAuthStartTime
        WIKI.logger.info(`[Telegram] Session cleaned`)
        
        WIKI.logger.info(`[Telegram] Calling verify callback...`)
        
        this._verify(req, null, null, profile, (err, user) => {
          if (err) {
            WIKI.logger.error('[Telegram] Verify callback error:', err)
            WIKI.logger.error('[Telegram] Error message:', err.message)
            WIKI.logger.error('[Telegram] Error stack:', err.stack)
            return self.fail(err.message)
          }
          if (!user) {
            WIKI.logger.error('[Telegram] Verify callback returned no user')
            return self.fail('User not found')
          }
          
          WIKI.logger.info(`[Telegram] Verify callback successful`)
          WIKI.logger.info(`[Telegram] Authenticated user ID: ${user.id}`)
          WIKI.logger.info(`[Telegram] Total auth time: ${Date.now() - authStartTime}ms`)
          WIKI.logger.info(`[Telegram] === Authentication successful ===`)
          
          return self.success(user)
        })
        
      } catch (err) {
        WIKI.logger.error(`[Telegram] CRITICAL ERROR in authenticate():`)
        WIKI.logger.error(`[Telegram] Error name: ${err.name}`)
        WIKI.logger.error(`[Telegram] Error message: ${err.message}`)
        WIKI.logger.error(`[Telegram] Error stack:`, err.stack)
        WIKI.logger.error(`[Telegram] Error object:`, err)
        return this.fail(err.message || 'Authentication failed')
      }
    }

    WIKI.logger.info(`[Telegram] Registering strategy with passport (key: ${conf.key})`)
    
    passport.use(conf.key, new TelegramStrategy({
      name: conf.key,
      callbackURL: conf.callbackURL,
      clientID: conf.clientId,
      clientSecret: conf.clientSecret,
      scope: ['openid', 'profile']
    }, async (req, accessToken, refreshToken, profile, done) => {
      WIKI.logger.info(`[Telegram] === Verify callback called ===`)
      WIKI.logger.info(`[Telegram] Profile ID: ${profile.id}`)
      WIKI.logger.info(`[Telegram] Profile username: ${profile.username}`)
      WIKI.logger.info(`[Telegram] Profile provider: ${profile.provider}`)
      
      try {
        WIKI.logger.info(`[Telegram] Calling WIKI.models.users.processProfile...`)
        
        const user = await WIKI.models.users.processProfile({
          providerKey: conf.key,
          profile: profile
        })
        
        WIKI.logger.info(`[Telegram] processProfile completed successfully`)
        WIKI.logger.info(`[Telegram] User ID: ${user.id}`)
        WIKI.logger.info(`[Telegram] User email: ${user.email}`)
        
        done(null, user)
      } catch (err) {
        WIKI.logger.error(`[Telegram] CRITICAL ERROR in verify callback:`)
        WIKI.logger.error(`[Telegram] Error name: ${err.name}`)
        WIKI.logger.error(`[Telegram] Error message: ${err.message}`)
        WIKI.logger.error(`[Telegram] Error stack:`, err.stack)
        done(err, null)
      }
    }))
    
    WIKI.logger.info(`[Telegram] Strategy registered successfully`)
    WIKI.logger.info(`[Telegram] === Initialization complete ===`)
  }
}

function decodeJWT(token) {
  WIKI.logger.info(`[Telegram] decodeJWT called`)
  WIKI.logger.info(`[Telegram] Token length: ${token.length}`)
  
  try {
    const parts = token.split('.')
    WIKI.logger.info(`[Telegram] JWT parts count: ${parts.length}`)
    
    if (parts.length !== 3) {
      WIKI.logger.error(`[Telegram] Invalid JWT structure - expected 3 parts, got ${parts.length}`)
      return null
    }
    
    WIKI.logger.info(`[Telegram] Header (first 50 chars): ${parts[0].substring(0, 50)}...`)
    WIKI.logger.info(`[Telegram] Payload (first 50 chars): ${parts[1].substring(0, 50)}...`)
    WIKI.logger.info(`[Telegram] Signature (first 50 chars): ${parts[2].substring(0, 50)}...`)
    
    const payload = parts[1]
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/')
    WIKI.logger.info(`[Telegram] Base64 decoded (first 50 chars): ${base64.substring(0, 50)}...`)
    
    const jsonString = Buffer.from(base64, 'base64').toString('utf8')
    WIKI.logger.info(`[Telegram] JSON string (first 200 chars): ${jsonString.substring(0, 200)}`)
    
    const parsed = JSON.parse(jsonString)
    WIKI.logger.info(`[Telegram] JSON parsed successfully`)
    WIKI.logger.info(`[Telegram] Payload keys: ${Object.keys(parsed).join(', ')}`)
    
    return parsed
  } catch (err) {
    WIKI.logger.error(`[Telegram] JWT decode error:`, err.message)
    WIKI.logger.error(`[Telegram] JWT decode stack:`, err.stack)
    return null
  }
}
