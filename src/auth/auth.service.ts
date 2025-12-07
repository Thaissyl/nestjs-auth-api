import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { Prisma } from "@prisma/client";

@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService
        // private jwt: JwtService,
        // private config: ConfigService,
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
                },
            });
            return user
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken');
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
        delete user.hash;
        return user
    }

}

