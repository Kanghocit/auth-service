import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

declare global {
  namespace Express {
    interface Request {
      user?: any;
      cookies: {
        Authorization?: string;
        refreshToken?: string;
      };
    }
  }
}

export const identifyUser = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let token = req.cookies.Authorization || req.headers["authorization"];

  if (!token) {
    res.status(401).json({ message: "Token is missing" });
    return;
  }
  try {
    const userToken = token.split(" ")[1];
    const jwtVerified = jwt.verify(userToken, process.env.ACCESS_TOKEN_SECRET!);
    if (jwtVerified) {
      req.user = jwtVerified;
      next();
    } else {
      res.status(401).json({ message: "Error verifying token" });
      return;
    }
  } catch (error) {
    res.status(401).json({ message: "Unauthorized", error: error });
    return;
  }
};

export const validateRefreshToken = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const refreshToken = req.cookies["refreshToken"];
  if (!refreshToken) {
    res.status(401).json({ message: "Refresh token is missing" });
    return;
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid refresh token" });
    return;
  }
};
