import { NextFunction, Request, Response } from "express";
import uuid4 from "uuid4";

export const generateSessionId = () =>{
  return (req: Request, res: Response, next: NextFunction) =>{
  const sessionId = uuid4()
  req.sessionId = sessionId
  return next()
}
}

