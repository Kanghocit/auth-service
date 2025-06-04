import { Request, RequestHandler, Response } from "express";
import { validateRegister, validateLogin } from "../middlewares/validator";
import User from "../models/user.modal";
import { hashPassword } from "../utils/hashPassword";
import { comparePassword } from "../utils/comparePassword";
import jwt from "jsonwebtoken";

export const register: RequestHandler = async (req: Request, res: Response) => {
  const { email, password: userPassword } = req.body;
  try {
    const { error } = validateRegister.validate({
      email,
      password: userPassword,
    });
    if (error) {
      res.status(401).json({ message: error.message });
      return;
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(400).json({ message: "User already exists" });
      return;
    }
    const hashedPassword = await hashPassword(userPassword, 12);

    const newUser = new User({ email, password: hashedPassword });

    const result = await newUser.save();
    const { password: _, ...userWithoutPassword } = result.toObject();

    res.status(201).json({
      message: "User created successfully",
      result: userWithoutPassword,
    });
  } catch (error) {
    res.status(500).json({
      error: error,
    });
  }
};

export const login: RequestHandler = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const { error } = validateLogin.validate({
      email,
      password,
    });
    if (error) {
      res.status(401).json({ message: error.message });
      return;
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ message: "Invalid password" });
      return;
    }
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        verified: user.verified,
        role: user.role,
      },
      process.env.TOKEN_SECRET!,
      {
        expiresIn: "8h",
      }
    );
    res.cookie("Authorization", `Bearer ${token}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 8 * 60 * 60 * 1000,
    });

    const { password: _, ...userWithoutPassword } = user.toObject();
    res.status(200).json({
      message: "Login successfully!",
      token,
      result: userWithoutPassword,
    });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};

export const logout: RequestHandler = (req: Request, res: Response) => {
  res.clearCookie("Authorization");
  res.status(200).json({ message: "Logout successfully!" });
};
