export interface LoginResponse {
  accessToken: string;
  accessExpiresAt: string;   // ISO string
  refreshToken: string;
  refreshExpiresAt: string;  // ISO string
  userId: string;
  role: string;
  name?: string | null;
  surname?: string | null;
}
