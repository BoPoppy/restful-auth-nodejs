import express from 'express';
import { get, merge } from 'lodash';

import { getUserBySessionToken } from '../db/users';

export const isAuthenticated = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  try {
    const sessionToken = req.cookies['FELIX-AUTH'];
    if (!sessionToken) return res.sendStatus(403);
    const existingUser = await getUserBySessionToken(sessionToken);
    if (!existingUser) return res.sendStatus(403);
    merge(req, { identity: existingUser });
    return next();
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};

export const isOwner = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  try {
    const { id } = req.params;
    const currentUserId = get(req, 'identity._id') as string;

    if (!currentUserId) return res.sendStatus(403);
    if (currentUserId.toString() === id) {
      merge(req, { isOwner: true });
    } else {
      merge(req, { isOwner: false });
    }
    return next();
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};
