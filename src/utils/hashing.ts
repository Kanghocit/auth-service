import { hash } from "bcrypt";
import { createHmac } from "crypto";

export const hashPassword = (password: string, salt: number) => {
  const result = hash(password, salt);
  return result;
};
export const hmacProcess = (value: string, key: string) => {
  const hmac = createHmac("sha256", key);
  hmac.update(value);
  return hmac.digest("hex");
};
