/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode, verify } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const users = await UserModel.findAll()

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          try {
            const parsedToken = verify(userToken, 'your-secret-key', { algorithms: ['HS256'] })
            lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken.iat * 1000).getTime()) : null
          } catch (err) {
            console.error('Invalid token:', err)
          }
        }

        return {
          ...user.dataValues,
          password: user.password?.replace(/./g, '*'),
          totpSecret: user.totpSecret?.replace(/./g, '*'),
          lastLoginTime
        }
      })
    })
  } catch (error) {
    next(error)
  }
}

export default () => retrieveUserList
