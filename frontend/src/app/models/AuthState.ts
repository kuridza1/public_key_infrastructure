import { BasicUser } from "./BasicUser";

export type AuthState = {
  accessToken: string | null;
  accessExpiresAt: string | null;
  refreshToken: string | null;
  refreshExpiresAt: string | null;
  user: BasicUser | null;
};