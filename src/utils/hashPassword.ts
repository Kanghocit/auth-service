import { hash } from "bcrypt";

export const hashPassword = (password: string, salt: number) => {
  const result = hash(password, salt);
  return result;
};
