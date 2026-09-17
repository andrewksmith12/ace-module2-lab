/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { BlockList, isIP } from 'node:net'
import * as dns from 'node:dns/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const blockList = new BlockList()
blockList.addSubnet('0.0.0.0', 8, 'ipv4')
blockList.addSubnet('10.0.0.0', 8, 'ipv4')
blockList.addSubnet('100.64.0.0', 10, 'ipv4')
blockList.addSubnet('127.0.0.0', 8, 'ipv4')
blockList.addSubnet('169.254.0.0', 16, 'ipv4')
blockList.addSubnet('172.16.0.0', 12, 'ipv4')
blockList.addSubnet('192.0.0.0', 24, 'ipv4')
blockList.addSubnet('192.0.2.0', 24, 'ipv4')
blockList.addSubnet('192.88.99.0', 24, 'ipv4')
blockList.addSubnet('192.168.0.0', 16, 'ipv4')
blockList.addSubnet('198.18.0.0', 15, 'ipv4')
blockList.addSubnet('198.51.100.0', 24, 'ipv4')
blockList.addSubnet('203.0.113.0', 24, 'ipv4')
blockList.addSubnet('224.0.0.0', 4, 'ipv4')
blockList.addSubnet('240.0.0.0', 4, 'ipv4')
blockList.addAddress('255.255.255.255', 'ipv4')

blockList.addAddress('::', 'ipv6')
blockList.addAddress('::1', 'ipv6')
blockList.addSubnet('::', 96, 'ipv6')
blockList.addSubnet('fc00::', 7, 'ipv6')
blockList.addSubnet('fe80::', 10, 'ipv6')
blockList.addSubnet('ff00::', 8, 'ipv6')
blockList.addSubnet('2001:db8::', 32, 'ipv6')
blockList.addSubnet('64:ff9b::', 96, 'ipv6')
blockList.addSubnet('100::', 64, 'ipv6')

async function isSafeUrl (urlString: string): Promise<boolean> {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false
  }
  let parsed: URL
  try {
    parsed = new URL(urlString)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }
  if (parsed.port !== '' && parsed.port !== '80' && parsed.port !== '443') {
    return false
  }

  let hostname = parsed.hostname.trim()
  if (!hostname) {
    return false
  }
  hostname = hostname.replace(/^\[|\]$/g, '')
  const lowerHost = hostname.toLowerCase()
  if (lowerHost === 'localhost' || lowerHost.endsWith('.localhost') || lowerHost.endsWith('.local') || lowerHost.endsWith('.internal')) {
    return false
  }

  const ipVer = isIP(hostname)
  if (ipVer !== 0) {
    const family = ipVer === 6 ? 'ipv6' : 'ipv4'
    return !blockList.check(hostname, family)
  }

  try {
    const addresses = await dns.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const addr of addresses) {
      const family = addr.family === 6 ? 'ipv6' : 'ipv4'
      if (blockList.check(addr.address, family)) {
        return false
      }
    }
  } catch {
    return false
  }
  return true
}

async function fetchSafeUrl (initialUrl: string, maxRedirects = 3): Promise<Response> {
  let currentUrl = initialUrl
  for (let i = 0; i <= maxRedirects; i++) {
    const isSafe = await isSafeUrl(currentUrl)
    if (!isSafe) {
      throw new Error('Disallowed image URL')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('Redirect without Location header')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!await isSafeUrl(url)) {
          res.status(400)
          next(new Error('Unrecognized image URL'))
          return
        }
        try {
          const response = await fetchSafeUrl(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (error instanceof Error && error.message === 'Disallowed image URL') {
            res.status(400)
            next(error)
            return
          }
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
