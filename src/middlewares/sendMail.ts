import nodemailer from "nodemailer";

export const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_ADDRESS_SENDER,
    pass: process.env.EMAIL_PASSWORD_SENDER,
  },
});
