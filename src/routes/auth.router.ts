import { Router, RequestHandler } from "express";
import {
  changePassword,
  getUserByEmail,
  login,
  logout,
  register,
  sendForgotPasswordCode,
  sendVerificationCode,
  updatePasswordAfterVerifyCode,
  verifyForgotPasswordCode,
  verifyVerificationCode,
} from "../controllers/auth.controller";

import {
  identifyUser,
  validateRefreshToken,
} from "../middlewares/identification";

import { refreshAccessToken } from "../utils/handleToken";

const router = Router();

router.post("/register", register);

router.post("/login", login);

router.post("/logout", identifyUser, logout as RequestHandler);

//send verification code
router.patch(
  "/send-verification-code",
  identifyUser,
  sendVerificationCode as RequestHandler
);

//verify verification code
router.patch(
  "/verify-verification-code",
  identifyUser,
  verifyVerificationCode as RequestHandler
);

router.patch(
  "/change-password",
  identifyUser,
  changePassword as RequestHandler
);

//get user
router.get("/get-user", identifyUser, getUserByEmail as RequestHandler);

router.post(
  "/refresh-token",
  validateRefreshToken,
  refreshAccessToken as RequestHandler
);

//forgot password
router.patch(
  "/send-forgot-password-code",
  identifyUser,
  sendForgotPasswordCode as RequestHandler
);

//verify forgot password code
router.patch(
  "/verify-forgot-password-code",
  identifyUser,
  verifyForgotPasswordCode as RequestHandler
);

//update password after verify code
router.patch(
  "/update-password-after-verify-code",
  identifyUser,
  updatePasswordAfterVerifyCode as RequestHandler
);

export default router;
