import { Request, RequestHandler, Response } from "express";
import { validate } from "../middlewares/validator";
import User from "../models/user.modal";
import { hashPassword } from "../utils/hashPassword";

export const register: RequestHandler = async (req: Request, res: Response) => {
  const { email, password: userPassword } = req.body;
  try {
    const { error } = validate.validate({
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

export const login: RequestHandler = (req: Request, res: Response) => {
  res.json({ message: "Login successfully!" });
};
