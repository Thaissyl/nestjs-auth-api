import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { Prisma } from "@prisma/client";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) { }

    async signup(dto: AuthDto) {
        //generate the password hash
        const hash = await argon.hash(dto.password);

        //save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                select: {
                    id: true,
                    email: true,
                    createdAt: true,
                    status: true,
                },
            });
            const tokens = await this.getTokens(user.id, user.email);
            await this.updateRtHash(user.id, tokens.refresh_token);
            return tokens;
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Email already exists');
                }
            }
            throw error;
        }
    }

    async signin(dto: AuthDto) {
        //find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
            select: {
                id: true,
                email: true,
                createdAt: true,
                hash: true,
            },
        });
        //if user does not exist throw exception
        if (!user) {
            throw new ForbiddenException('Credentials incorrect');
        }
        //compare password
        const pwMatches = await argon.verify(user.hash, dto.password);
        if (!pwMatches) {
            throw new ForbiddenException('Credentials incorrect');
        }
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);
        return tokens;
    }

    async logout(userId: number) {
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashedRt: {
                    not: null,
                },
            },
            data: {
                hashedRt: null,
            },
        });
    }

    async refreshTokens(userId: number, rt: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        });
        if (!user || !user.hashedRt) {
            throw new ForbiddenException('Access Denied');
        }

        const rtMatches = await argon.verify(user.hashedRt, rt);
        if (!rtMatches) {
            throw new ForbiddenException('Access Denied');
        }

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);
        return tokens;
    }

    async updateRtHash(userId: number, rt: string) {
        const hash = await argon.hash(rt);
        await this.prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                hashedRt: hash,
            },
        });
    }

    async getTokens(userId: number, email: string): Promise<{
        access_token: string;
        refresh_token: string;
    }> {
        const payload = {
            sub: userId,
            email,
        };

        const [at, rt] = await Promise.all([
            this.jwt.signAsync(payload, {
                expiresIn: '15m',
                secret: this.config.get('JWT_SECRET'),
            }),
            this.jwt.signAsync(payload, {
                expiresIn: '7d',
                secret: this.config.get('JWT_REFRESH_SECRET'),
            }),
        ]);

        return {
            access_token: at,
            refresh_token: rt,
        };
    }
}
