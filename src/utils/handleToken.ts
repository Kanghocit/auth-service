import { Request, Response } from "express";
import jwt from "jsonwebtoken";

interface User {
  _id: string;
  name: string;
  email: string;
  verified: boolean;
  role: string;
  canUpdatePassword: boolean;
}

// Tạo access token
export const genarateAccessToken = (user: User) => {
  return jwt.sign(
    {
      userId: user._id,
      name: user.name,
      email: user.email,
      verified: user.verified,
      canUpdatePassword: user.canUpdatePassword,
      role: user.role,
    },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );
};
// Tạo refresh token
export const genarateRefreshToken = (user: User) => {
  return jwt.sign(
    {
      userId: user._id,
    },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: "7d",
    }
  );
};
// Làm mới access token từ refresh token
export const refreshAccessToken = (req: Request, res: Response) => {
  const refreshToken = req.cookies["refreshToken"];
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token is missing" });
  }
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET!,
    (err: any, user: any) => {
      if (err) {
        return res.status(401).json({ message: "Invalid refresh token" });
      }
      const accessToken = genarateAccessToken(user as User);
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 15 * 60 * 1000,
      });
      res.status(200).json({
        message: "Access token refreshed",
        accessToken,
      });
    }
  );
};
