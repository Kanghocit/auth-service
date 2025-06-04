import { compare } from "bcrypt";

export const comparePassword = async (
  password: string,
  hashedPassword: string
) => {
  const result = await compare(password, hashedPassword);
  return result;
};
