import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto/auth.dto";
import * as argon from "argon2";
import { Prisma } from '@prisma/client';

@Injectable({})
export class AuthService {

    constructor(private prisma: PrismaService) { }

    async signUp(dto: AuthDto) {
        // find the user by email
        const userExists = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        });
        // if user does exist throw exception
        if (userExists) {
            throw new ForbiddenException(
                'Email already exists',
            );
        }
        // generate the password hash
        const hash = await argon.hash(dto.password);
        // save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });

            return user;
            //   return this.signToken(user.id, user.email);
        } catch (error) {
            if (
                error instanceof
                Prisma.PrismaClientKnownRequestError
            ) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException(
                        'Credentials taken',
                    );
                }
            }
            throw error;
        }
    }

    async signIn(dto: AuthDto) {
        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        });
        // if user does not exist throw exception
        if (!user) {
            throw new ForbiddenException(
                'Email incorrect',
            );
        }

        // compare password
        const psMatches = await argon.verify(user.hash, dto.password);
        // if password incorrect throw exception
        if(!psMatches) {
            throw new ForbiddenException(
                'Password incorrect',
            );
        }

        // send back the user info
        delete user.hash;
        return user;
    }
}