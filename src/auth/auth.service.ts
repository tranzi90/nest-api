import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from './dto';
import * as argon2 from "argon2";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credentials incorrect');

    const pwMatches = await argon2.verify(user.hash, dto.password);

    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

    delete user.hash;
    return user;
  }
  async signup(dto: AuthDto) {
    const hash = await argon2.hash(dto.password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;
      return user;
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw e;
    }
  }
}
