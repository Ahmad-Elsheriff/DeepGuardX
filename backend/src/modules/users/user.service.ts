import { NextFunction, Request, Response } from "express";

class UserService {
  signUp = (req: Request, res: Response, next: NextFunction) =>{
    return res.status(201).json({message: 'Success'})
  }
  signIn = (req: Request, res: Response, next: NextFunction) =>{
    return res.status(201).json({message: 'Success'})
  }
  }


export default new UserService()


