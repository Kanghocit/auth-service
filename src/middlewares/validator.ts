import Joi from "joi";

export const validate = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: ["com", "net"] } })
    .required()
    .min(5)
    .max(100),
  password: Joi.string()
    .required()
    .min(8)
    .max(100)
    .pattern(
      new RegExp(
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};'\"\\|,.<>/?]).{8,}$"
      )
    ),
});
