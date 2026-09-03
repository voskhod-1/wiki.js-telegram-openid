/* global WIKI */

const crypto = require('crypto')
const https = require('https')
const url = require('url')

module.exports = {
  init(passport, conf) {
    WIKI.logger.info('[Telegram] Initializing strategy')
    WIKI.logger.info(`[Telegram] Config: clientID=${conf.clientId}, callbackURL=${conf.callbackURL}`)
    
    // Читаем опциональный параметр из конфига
    const customApiUrl = conf.customApiUrl ? conf.customApiUrl.trim() : null;
    
    let proxyHostname = null;
    let proxyPrefix = '';
    let issuerBase = 'https://oauth.telegram.org';

    if (customApiUrl) {
      try {
        const parsedProxy = new URL(customApiUrl);
        proxyHostname = parsedProxy.hostname;
        proxyPrefix = parsedProxy.pathname.replace(/\/$/, ''); 
        issuerBase = `https://${proxyHostname}${proxyPrefix}`;
        
        WIKI.logger.info(`[Telegram] ✅ Custom API URL is ACTIVE: ${customApiUrl}`);
        WIKI.logger.info(`[Telegram] Proxy Host: ${proxyHostname}, Prefix: ${proxyPrefix}`);
      } catch (e) {
        WIKI.logger.error(`[Telegram] ❌ Invalid customApiUrl provided: "${customApiUrl}". Falling back to default.`);
        WIKI.logger.error(`[Telegram] Error:`, e.message);
      }
    } else {
      WIKI.logger.info('[Telegram] ℹ️ No custom API URL provided. Using default Telegram servers.');
    }

    const authURL = `${issuerBase}/auth`;
    const tokenURL = `${issuerBase}/token`;

    // Функция HTTP POST запроса
    function postJSON(originalEndpoint, data, clientId, clientSecret) {
      return new Promise((resolve, reject) => { // <-- ИСПРАВЛЕНО: добавлена открывающая скобка {
        WIKI.logger.info(`[Telegram] HTTP POST to original: ${originalEndpoint}`)
        
        const parsedOriginal = new URL(originalEndpoint);
        
        // Динамическое определение хоста и пути
        const targetHostname = proxyHostname || parsedOriginal.hostname;
        const targetPath = proxyHostname 
          ? proxyPrefix + parsedOriginal.pathname + (parsedOriginal.search || '')
          : parsedOriginal.pathname + (parsedOriginal.search || '');

        if (proxyHostname) {
          WIKI.logger.info(`[Telegram] Routing through proxy: https://${targetHostname}${targetPath}`);
        }
        
        const postData = new url.URLSearchParams(data).toString()
        const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
        
        const options = {
          hostname: targetHostname,
          port: parsedOriginal.protocol === 'https:' ? 443 : 80,
          path: targetPath,
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData),
            'Authorization': `Basic ${basicAuth}`
          }
        }
        
        // Если используем прокси, подменяем Host на оригинальный
        if (proxyHostname) {
          options.headers['Host'] = parsedOriginal.hostname;
        }
        
        WIKI.logger.info(`[Telegram] Request options:`, {
          hostname: options.hostname,
          path: options.path,
          method: options.method,
          headers: {
            ...options.headers,
            'Authorization': 'Basic ***'
          }
        })
        
        const req = https.request(options, (res) => {
          WIKI.logger.info(`[Telegram] Response received - Status: ${res.statusCode}`)
          
          let body = ''
          res.on('data', (chunk) => { body += chunk })
          
          res.on('end', () => {
            if (res.statusCode !== 200) {
              WIKI.logger.error(`[Telegram] HTTP Error: ${res.statusCode}`)
              try {
                const errorData = JSON.parse(body)
                reject(new Error(`Telegram API error (${res.statusCode}): ${errorData.error_description || errorData.error || 'Unknown error'}`))
              } catch (e) {
                reject(new Error(`HTTP ${res.statusCode}: ${body}`))
              }
              return
            }
            
            try {
              const jsonData = JSON.parse(body)
              resolve(jsonData)
            } catch (e) {
              reject(new Error(`Failed to parse response: ${body}`))
            }
          })
        })
        
        req.on('error', (err) => {
          WIKI.logger.error(`[Telegram] Request error:`, err.message)
          reject(err)
        })
        
        req.write(postData)
        req.end()
      }) // <-- Закрывающая скобка Promise
    }

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
        
        if (!req.query || !req.query.code) {
          const state = crypto.randomBytes(32).toString('hex')
          const codeVerifier = crypto.randomBytes(32).toString('base64url')
          const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url')
          
          if (!req.session) req.session = {}
          req.session.telegramState = state
          req.session.telegramCodeVerifier = codeVerifier
          
          const authParams = {
            client_id: this._clientID,
            redirect_uri: this._callbackURL,
            response_type: 'code',
            scope: this._scope.join(' '),
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
          }
          
          const redirectURL = `${authURL}?` + new URLSearchParams(authParams).toString()
          return this.redirect(redirectURL)
        }
        
        const code = req.query.code
        const state = req.query.state
        
        if (!req.session || !req.session.telegramState || !req.session.telegramCodeVerifier) {
          return this.fail('Invalid session state', 403)
        }
        
        if (state !== req.session.telegramState) {
          return this.fail('Invalid state parameter', 403)
        }
        
        const tokenData = await postJSON(tokenURL, {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: this._callbackURL,
          code_verifier: req.session.telegramCodeVerifier
        }, this._clientID, this._clientSecret)
        
        if (!tokenData.id_token) {
          return this.fail('No ID token received', 500)
        }
        
        const payload = decodeJWT(tokenData.id_token)
        if (!payload) return this.fail('Failed to decode ID token', 500)
        
        const telegramId = payload.sub || payload.id
        const username = payload.preferred_username
        const name = payload.name
        const picture = payload.picture
        
        if (!username || !username.trim()) {
          return this.fail('Telegram account must have a username', 400)
        }
        
        const cleanIdentifier = username.toLowerCase().replace(/[^a-z0-9_]/g, '_')
        const generatedEmail = `${cleanIdentifier}@telegram.org`
        
        const profile = {
          id: String(telegramId),
          username: username,
          displayName: name || username,
          name: { givenName: name || username },
          emails: [{ value: generatedEmail, primary: true }],
          photos: picture ? [{ value: picture }] : [],
          provider: 'telegram'
        }
        
        delete req.session.telegramState
        delete req.session.telegramCodeVerifier
        
        this._verify(req, null, null, profile, (err, user) => {
          if (err) return self.fail(err.message)
          if (!user) return self.fail('User not found')
          return self.success(user)
        })
        
      } catch (err) {
        WIKI.logger.error(`[Telegram] CRITICAL ERROR in authenticate():`, err)
        return this.fail(err.message || 'Authentication failed')
      }
    }

    passport.use(conf.key, new TelegramStrategy({
      name: conf.key,
      callbackURL: conf.callbackURL,
      clientID: conf.clientId,
      clientSecret: conf.clientSecret,
      scope: ['openid', 'profile']
    }, async (req, accessToken, refreshToken, profile, done) => {
      try {
        const user = await WIKI.models.users.processProfile({
          providerKey: conf.key,
          profile: profile
        })
        done(null, user)
      } catch (err) {
        WIKI.logger.error(`[Telegram] CRITICAL ERROR in verify callback:`, err)
        done(err, null)
      }
    }))
    
    WIKI.logger.info(`[Telegram] Strategy registered successfully`)
  }
}

function decodeJWT(token) {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    
    const payload = parts[1]
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/')
    const jsonString = Buffer.from(base64, 'base64').toString('utf8')
    
    return JSON.parse(jsonString)
  } catch (err) {
    WIKI.logger.error(`[Telegram] JWT decode error:`, err.message)
    return null
  }
}
