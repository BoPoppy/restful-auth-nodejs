import express from 'express';
import { deleteUserById, getUserById, getUsers, updateUserById } from '../db/users';
import { get } from 'lodash';

export const getAllUsers = async (req: express.Request, res: express.Response) => {
  try {
    const users = await getUsers();
    return res.status(200).json(users);
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};

export const deleteUser = async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const isOwner = get(req, 'isOwner') as boolean;
    if (isOwner) return res.sendStatus(403);
    const deletedUser = await deleteUserById(id);
    return res.json(deletedUser);
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};

export const updateUser = async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const isOwner = get(req, 'isOwner') as boolean;
    if (!isOwner) return res.sendStatus(403);
    const { username } = req.body;
    if (!username) return res.sendStatus(400);
    const user = await getUserById(id);
    user.username = username;
    await user.save();

    return res.status(200).json(user).end();
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};
