import { NextFunction, Response } from "express";
import jwt, { Secret } from "jsonwebtoken";
import { Request } from "express";

export const SECRET: Secret = "SECr3t";

export const authenticateJwt = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET, (err: any, payload: any) => {
      if (err) {
        return res.sendStatus(403);
      }

      if (!payload) {
        return res.sendStatus(403);
      }

      // Use set instead of directly modifying headers
      res.set("userId", payload.id);
      next();
    });
  } else {
    res.sendStatus(401);
  }
};
