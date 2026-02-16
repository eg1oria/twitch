import {
	Injectable,
	NotFoundException,
	UnauthorizedException
} from '@nestjs/common'
import { verify } from 'argon2'
import type { Request } from 'express'

import { PrismaService } from '@/src/core/prisma/prisma.service'

import { LoginInput } from './inputs/login.input'

@Injectable()
export class SessionService {
	constructor(private readonly prismaService: PrismaService) {}

	async login(req: Request, input: LoginInput) {
		const { login, password } = input

		const user = await this.prismaService.user.findFirst({
			where: {
				OR: [
					{
						username: { equals: login }
					},
					{
						email: { equals: login }
					}
				]
			}
		})

		if (!user) {
			throw new NotFoundException('Пользователь не найден')
		}

		const isValidPassword = verify(user.password, password)

		if (!isValidPassword) {
			throw new UnauthorizedException('Неверный пароль')
		}
	}
}
