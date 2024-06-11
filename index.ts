import path from 'path'
import express, { Express, Request, Response, NextFunction } from 'express'
import proxy from 'express-http-proxy'
import { Issuer, Strategy } from 'openid-client'
import passport from 'passport'
import session, { MemoryStore } from 'express-session'
import RedisStore from 'connect-redis'
import { createClient } from 'redis'

const ServerConfig = require('@vapaaradikaali/helpers.js/lib/ServerConfig')
const config = new ServerConfig()
config.loadFile(path.join(__dirname, 'config', 'defaults'))
config.loadFile(path.join(__dirname, 'config', 'local'), true)

type User = Record<string, any>

declare module 'express-session' {
  interface SessionData {
    user?: User,
    redirectUrl?: string
  }
}

const app: Express = express()

const init = async () => {
  const issuerUrl: string = `${config.get('keycloak.provider', '').replace(/\/$/, '')}/realms/${config.get('keycloak.realm')}`
  const issuer = await Issuer.discover(issuerUrl)

  const checkAuthenticated = (req: Request, res: Response, next: NextFunction) => {
    if (req.isAuthenticated()) {
      return next()
    }

    res.redirect('/test')
  }

  const client = new issuer.Client({
    client_id: config.get('keycloak.client_id'),
    client_secret: config.get('keycloak.client_secret'),
    redirect_uris: [
      `${config.get('proxy.host')}/auth/login`
    ],
    post_logout_redirect_uris: [
      `${config.get('proxy.host')}/logout`
    ],
    response_types: ['code']
  })

  // const store = new MemoryStore()
  const redisClient = createClient()
  redisClient.connect()

  const store = new RedisStore({
    client: redisClient
  })

  app.use(session({
    secret: config.get('server.session_id'),
    resave: true,
    saveUninitialized: false,
    store,
    name: 'kc.session'
  }))

  app.use(passport.initialize())
  app.use(passport.authenticate('session'))
  app.set('trust proxy', true)

  passport.use('oidc', new Strategy({ client }, async (tokenSet: any, userInfo: any, done: Function) => {
    return done(null, tokenSet.claims())
  }))

  passport.serializeUser((user: Object, done: Function) => {
    done(null, user)
  })

  passport.deserializeUser((user: Object, done: Function) => {
    done(null, user)
  })

  app.get('/logout', (req: Request, res: Response, next: NextFunction) => {
    req.logOut((err: any) => {
      if (err) {
        res.send(err.message)
        return
      }

      req.session.destroy((err) => {})
      res.send('Logged out\n')
    })
  })

  app.get('/auth/login', (req: Request, res: Response, next: NextFunction) => {
    if (req.isAuthenticated()) {
      console.log('-- is authenticated')
      if (req.session.redirectUrl) {
        console.log('-- has redirectUrl', req.session.redirectUrl)
        res.redirect(req.session.redirectUrl)
        req.session.redirectUrl = undefined
        return
      }

      console.log('-- no redirect url')
      return res.redirect('/')
    }

    passport.authenticate('oidc', {
      successRedirect: `${config.get('proxy.host')}/auth/login`,
      keepSessionInfo: true
    })(req, res, next)
  })

  app.get('/auth/login', (req: Request, res: Response, next: NextFunction) => {
    next()
  })

  app.use((req: Request, res: Response, next: NextFunction) => {
    console.log('req.ip', req.ip, req.originalUrl)

    const whitelisted = config.get('whitelist', [])

    for (const ip of whitelisted) {
      if (ip === req.ip) {
        console.log('ip', req.ip, 'is whitelisted', ip)
        return next()
      }
    }

    const host = config.get('proxy.host', `${req.protocol}://${req.hostname}`)

    if (!req.isAuthenticated()) {
      req.session.redirectUrl = `${req.protocol}://${req.hostname}${req.originalUrl}`
      res.redirect(`${host}/auth/login`)
      return
    }

    return next()
  })

  const isPatternMatch = (pattern: string, url: string): Boolean => {
    if (pattern === '*') {
      return true
    }

    const regexp = new RegExp('^' + pattern.replace(/\//, '\\/'))

    return regexp.test(url)
  }

  app.use((req: Request, res: Response, next: NextFunction) => {
    const forwards: Record<string, number | string> = config.get('forwards', {})
    res.statusCode = config.get('proxy.status_code', 503)

    for (const pattern in forwards) {
      if (!isPatternMatch(pattern, req.originalUrl)) {
        console.log('-- no match', pattern, req.originalUrl)
        continue
      }

      if (typeof forwards[pattern] === 'number') {
        console.log('-- proxy request', req.ip, req.originalUrl, 'as a status code', forwards[pattern])
        res.statusCode = forwards[pattern] as number
        res.send('ok\n')
        return
      }

      const location = forwards[pattern] + req.originalUrl

      console.log('-- proxy request', req.ip, req.originalUrl, 'to', location)
      proxy(location)(req, res, next)
      return
    }

    res.send('Proxy failed to match the authenticated request\n')
  })

  app.listen(config.get('server.port'), () => {
    console.log('Listening to', config.get('server.port'))
  })
}

init()
  .catch((err) => {
    console.error(err)
    console.error(err.stack)
    process.exit(1)
  })