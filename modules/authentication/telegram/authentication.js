/* global WIKI */

// ------------------------------------
// Telegram Account (Manual OIDC - Passport-compatible)
// ------------------------------------

const crypto = require('crypto')
const https = require('https')
const url = require('url')

module.exports = {
  init(passport, conf) {
    const issuerURL = 'https://oauth.telegram.org'
    const authURL = `${issuerURL}/auth`
    const tokenURL = `${issuerURL}/token`

    // Функция HTTP POST запроса
    function postJSON(endpoint, data) {
      return new Promise((resolve, reject) => {
        const postData = new url.URLSearchParams(data).toString()
        const parsedUrl = new URL(endpoint)
        
        const options = {
          hostname: parsedUrl.hostname,
          port: 443,
          path: parsedUrl.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData)
          }
        }
        
        const req = https.request(options, (res) => {
          let body = ''
          res.on('data', (chunk) => body += chunk)
          res.on('end', () => {
            try {
              resolve(JSON.parse(body))
            } catch (e) {
              reject(new Error(`Failed to parse response: ${body}`))
            }
          })
        })
        
        req.on('error', reject)
        req.write(postData)
        req.end()
      })
    }

    // Создаем стратегию с правильным интерфейсом Passport
    const TelegramStrategy = function(options, verify) {
      this.name = options.name || 'telegram'
      this._verify = verify
      this._callbackURL = options.callbackURL
      this._clientID = options.clientID
      this._clientSecret = options.clientSecret
      this._scope = options.scope || ['openid', 'profile']
    }

    TelegramStrategy.prototype.authenticate = async function(req, options) {
      try {
        const self = this
        
        // Если нет code - делаем редирект на авторизацию
        if (!req.query || !req.query.code) {
          // Генерируем state и code_verifier для PKCE
          const state = crypto.randomBytes(32).toString('hex')
          const codeVerifier = crypto.randomBytes(32).toString('base64url')
          const codeChallenge = crypto.createHash('sha256')
            .update(codeVerifier)
            .digest('base64url')
          
          // Сохраняем в сессии
          req.session = req.session || {}
          req.session.telegramState = state
          req.session.telegramCodeVerifier = codeVerifier
          
          // Строим URL авторизации
          const redirectURL = `${authURL}?` + new URLSearchParams({
            client_id: this._clientID,
            redirect_uri: this._callbackURL,
            response_type: 'code',
            scope: this._scope.join(' '),
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
          }).toString()
          
          WIKI.logger.info(`[Telegram] Redirecting to: ${redirectURL}`)
          return this.redirect(redirectURL) // Используем this.redirect()
        }
        
        // Получаем code из запроса
        const code = req.query.code
        const state = req.query.state
        const savedState = req.session?.telegramState
        
        if (!savedState || state !== savedState) {
          return this.fail('Invalid state parameter', 403)
        }
        
        const codeVerifier = req.session.telegramCodeVerifier
        
        WIKI.logger.info(`[Telegram] Exchanging code for tokens...`)
        
        // Обмениваем code на токены
        const tokenData = await postJSON(tokenURL, {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: this._callbackURL,
          client_id: this._clientID,
          client_secret: this._clientSecret,
          code_verifier: codeVerifier
        })
        
        if (!tokenData.id_token) {
          WIKI.logger.error(`[Telegram] No id_token in response`)
          return this.fail('No ID token received', 500)
        }
        
        // Декодируем JWT
        const payload = decodeJWT(tokenData.id_token)
        
        if (!payload) {
          return this.fail('Failed to decode ID token', 500)
        }
        
        WIKI.logger.info(`[Telegram] Decoded payload: ${JSON.stringify(payload, null, 2)}`)
        
        const telegramId = payload.sub || payload.id
        const username = payload.preferred_username
        const name = payload.name
        const picture = payload.picture
        
        if (!username || !username.trim()) {
          return this.fail('Telegram account must have a username', 400)
        }
        
        // Генерируем email
        const cleanIdentifier = username.toLowerCase().replace(/[^a-z0-9_]/g, '_')
        const generatedEmail = `${cleanIdentifier}@telegram.org`
        
        // Создаем профиль для Wiki.js
        const profile = {
          id: String(telegramId),
          username: username,
          displayName: name || username,
          name: { givenName: name || username },
          emails: [{ value: generatedEmail, primary: true }],
          photos: picture ? [{ value: picture }] : [],
          provider: 'telegram'
        }
        
        // Вызываем verify функцию
        this._verify(req, null, null, profile, (err, user) => {
          if (err) {
            return self.fail(err.message)
          }
          if (!user) {
            return self.fail('User not found')
          }
          return self.success(user)
        })
        
        // Очищаем сессию
        delete req.session.telegramState
        delete req.session.telegramCodeVerifier
        
      } catch (err) {
        WIKI.logger.error(`[Telegram] Auth error:`, err)
        return this.fail(err.message)
      }
    }

    // Регистрируем стратегию
    passport.use(conf.key, new TelegramStrategy({
      name: conf.key,
      callbackURL: conf.callbackURL,
      clientID: conf.clientId,
      clientSecret: conf.clientSecret,
      scope: ['openid', 'profile']
    }, async (req, accessToken, refreshToken, profile, done) => {
      try {
        WIKI.logger.info(`[Telegram] Processing profile for user ${profile.id}`)
        
        const user = await WIKI.models.users.processProfile({
          providerKey: conf.key,
          profile: profile
        })
        
        done(null, user)
      } catch (err) {
        WIKI.logger.error(`[Telegram] Process profile error:`, err)
        done(err, null)
      }
    }))
  }
}

// Функция декодирования JWT
function decodeJWT(token) {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    
    const payload = parts[1]
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/')
    const jsonString = Buffer.from(base64, 'base64').toString('utf8')
    
    return JSON.parse(jsonString)
  } catch (err) {
    console.error('JWT decode error:', err)
    return null
  }
}
