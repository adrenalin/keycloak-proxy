import path from 'path'
import express, { Express, Request, Response, NextFunction } from 'express'
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

      res.send('Logged out\n')
    })
  })

  app.get('/auth/login', (req: Request, res: Response, next: NextFunction) => {

    if (req.isAuthenticated()) {
      if (req.session.redirectUrl) {
        res.redirect(req.session.redirectUrl)
        req.session.redirectUrl = undefined
        return
      }

      return next()
    }

    passport.authenticate('oidc', {
      successRedirect: '/auth/login',
      keepSessionInfo: true
    })(req, res, next)
  })

  app.get('/auth/login', (req: Request, res: Response, next: NextFunction) => {
    next()
  })

  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!req.isAuthenticated()) {
      req.session.redirectUrl = req.originalUrl
      res.redirect('/auth/login')
      return
    }

    res.status(202)
    res.send('OK\n')
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