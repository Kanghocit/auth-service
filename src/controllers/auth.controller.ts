import { Request, RequestHandler, Response } from "express";
import { validateRegister, validateLogin } from "../middlewares/validator";
import User from "../models/user.modal";
import { hashPassword, hmacProcess } from "../utils/hashing";
import { comparePassword } from "../utils/comparePassword";
import jwt from "jsonwebtoken";
import { transporter } from "../middlewares/sendMail";
import {
  genarateAccessToken,
  genarateRefreshToken,
} from "../utils/handleToken";

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
    const accessToken = genarateAccessToken(user as any);
    const refreshToken = genarateRefreshToken(user as any);

    res.cookie("Authorization", `Bearer ${accessToken}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 8 * 60 * 60 * 1000,
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const { password: _, ...userWithoutPassword } = user.toObject();
    res.status(200).json({
      message: "Login successfully!",
      accessToken,
      refreshToken,
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
  res.clearCookie("refreshToken");
  res.status(200).json({ message: "Logout successfully!" });
  return;
};

export const sendVerificationCode: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (user?.verified) {
      res.status(400).json({ message: "User already verified" });
      return;
    }
    const codeValue = Math.floor(100000 + Math.random() * 900000);
    let info = await transporter.sendMail({
      from: process.env.EMAIL_ADDRESS_SENDER,
      to: email,
      subject: "Your Verification Code",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 24px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <img src="https://upload.wikimedia.org/wikipedia/commons/c/ca/LinkedIn_logo_initials.png" alt="Logo" width="60" style="border-radius: 100%;"/>
          </div>
          
          <p style="margin-top: 20px; font-size: 15px;">Enter the 6-digit code below to verify your identity and regain access to your account.</p>
          
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px; background: #f4f4f4; padding: 16px; text-align: center; border-radius: 8px; margin: 20px 0;">
            ${codeValue}
          </div>
          
          <p style="margin-bottom: 30px;">Thanks for helping us keep your account secure.</p>
          
          <p>The PETSHOP</p>
      
          <hr style="margin: 30px 0;" />
      
          <p style="font-weight: bold;">When and where this happened:</p>
          <p>
            <strong>Date:</strong> ${new Date().toUTCString()}<br/>
            <strong>Operating System:</strong> Windows<br/>
            <strong>Browser:</strong> Chrome<br/>
            <strong>Approximate Location:</strong> Hanoi, Vietnam
          </p>
      
          <hr style="margin: 30px 0;" />
      
          <div style="text-align: center; color: #888; font-size: 12px;">
            <p>This email was sent for verification purposes.</p>
            <p>© 2025 Your Company, All rights reserved.</p>
          </div>
        </div>
        `,
    });

    if (info.accepted[0] === user?.email) {
      const hashedCode = hmacProcess(
        codeValue.toString(),
        process.env.CODE_SECRET!
      );
      user.verificationCode = hashedCode;
      user.verificationCodeValidation = Date.now();
      await user.save();
      res.status(200).json({ message: "Verification code sent successfully" });
    }
    res.status(400).json({ message: "Failed to send verification code" });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};

export const verifyVerificationCode: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email }).select("+verificationCode");
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }

    if (
      user?.verificationCodeValidation &&
      user?.verificationCodeValidation + 2 * 60 * 1000 < Date.now()
    ) {
      res.status(400).json({ message: "Verification code expired" });
      return;
    }

    const hashedCode = hmacProcess(code, process.env.CODE_SECRET!);
    if (user.verificationCode !== String(hashedCode)) {
      res.status(400).json({
        message: "Invalid verification code",
      });
      return;
    }
    user.verified = true;
    user.verificationCode = undefined;
    user.verificationCodeValidation = undefined;
    await user.save();

    const accessToken = genarateAccessToken(user as any);

    res.cookie("Authorization", `Bearer ${accessToken}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 60 * 1000,
    });

    res
      .status(200)
      .json({ message: "Verification code verified successfully" });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};

export const changePassword: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { userId, verified } = req.user;
    const { oldPassword, newPassword } = req.body;
    if (!verified) {
      res.status(401).json({
        message: "You are not verified",
        result: {
          userId,
          verified,
        },
      });
      return;
    }
    const user = await User.findById(userId).select("+password");
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }
    const isPasswordValid = await comparePassword(oldPassword, user.password);
    if (!isPasswordValid) {
      res.status(400).json({ message: "Invalid password" });
      return;
    }
    const hashedNewPassword = await hashPassword(newPassword, 12);
    user.password = hashedNewPassword;
    await user.save();
    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};

export const getUserByEmail: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }
    res.status(200).json({ message: "User found", result: user });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};

export const sendForgotPasswordCode: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }
    const codeValue = Math.floor(100000 + Math.random() * 900000);
    let info = await transporter.sendMail({
      from: process.env.EMAIL_ADDRESS_SENDER,
      to: email,
      subject: "Your Forgot Password Code",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 24px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <img src="https://upload.wikimedia.org/wikipedia/commons/c/ca/LinkedIn_logo_initials.png" alt="Logo" width="60" style="border-radius: 100%;"/>
          </div>
          
          <p style="margin-top: 20px; font-size: 15px;">Enter the 6-digit code below to change your password.</p>
       
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px; background: #f4f4f4; padding: 16px; text-align: center; border-radius: 8px; margin: 20px 0;">
            ${codeValue}
          </div>
        </div>
        `,
    });
    if (info.accepted[0] === user?.email) {
      const hashedCode = hmacProcess(
        codeValue.toString(),
        process.env.CODE_SECRET!
      );
      user.forgotPasswordCode = hashedCode;
      user.forgotPasswordCodeValidation = Date.now();
      await user.save();
      res
        .status(200)
        .json({ message: "Forgot password code sent successfully" });
    }
    res.status(400).json({ message: "Failed to send forgot password code" });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};
export const verifyForgotPasswordCode: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email }).select("+forgotPasswordCode");
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }
    if (
      user?.forgotPasswordCodeValidation &&
      user?.forgotPasswordCodeValidation + 2 * 60 * 1000 < Date.now()
    ) {
      res.status(400).json({ message: "Verification code expired" });
      return;
    }
    const hashedCode = hmacProcess(code, process.env.CODE_SECRET!);
    if (user.forgotPasswordCode !== String(hashedCode)) {
      res.status(400).json({ message: "Invalid verification code" });
      return;
    } else {
      user.canUpdatePassword = true;
      user.forgotPasswordCode = undefined;
      user.forgotPasswordCodeValidation = undefined;
      await user.save();
      const accessToken = genarateAccessToken(user as any);
      res.cookie("Authorization", `Bearer ${accessToken}`, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 30 * 60 * 1000,
      });
      res
        .status(200)
        .json({ message: "Forgot password code verified successfully" });
    }
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};

export const updatePasswordAfterVerifyCode: RequestHandler = async (
  req: Request,
  res: Response
) => {
  try {
    const { userId, canUpdatePassword } = req.user;
    const { newPassword } = req.body;
    if (!canUpdatePassword) {
      res.status(400).json({ message: "You cannot update password" });
      return;
    }
    const user = await User.findById(userId).select("+password");
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }
    const hashedNewPassword = await hashPassword(newPassword, 12);
    user.password = hashedNewPassword;
    user.canUpdatePassword = false;
    await user.save();
    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
};
