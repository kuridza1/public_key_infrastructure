import {Role} from './Role';

export interface BasicUser {
  id: string;
  role: Role;
  name?: string | null;
  surname?: string | null;
}
