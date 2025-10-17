export interface LoginRequest {
  email: string;
  password: string;
  deviceId?: string | null;
}
