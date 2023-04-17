import type { Adapter, Provider, Session, Settings, User } from '$lib';
import type { SafeResult } from '$lib/utils/types';
import type { PrismaClient } from '@prisma/client';
import secs from '$lib/utils/secs';

const Prisma = (prisma: PrismaClient): Adapter => {
	const type = 'prisma';
	const handleAccount = async (user: User, provider: Provider): Promise<SafeResult<User>> => {
		try {
			const account = await prisma.account.findUnique({
				where: {
					provider_providerAccountId: {
						providerAccountId: user.id,
						provider: provider.name
					}
				}
			});

			if (!account) {
				const newAccount = await prisma.account.create({
					data: {
						providerAccountId: user.id,
						provider: provider.name,
						user: {
							create: {
								name: user.name,
								email: user.email,
								picture: user.picture
							}
						}
					}
				});

				return {
					ok: true,
					data: {
						id: newAccount.userId,
						name: user.name,
						email: user.email,
						picture: user.picture
					}
				};
			} else {
				return {
					ok: true,
					data: {
						id: account.userId,
						name: user.name,
						email: user.email,
						picture: user.picture
					}
				};
			}
		} catch (err) {
			return {
				ok: false,
				error: 'Failed to update account model.'
			};
		}
	};

	const createSession = async (user: User, settings: Settings): Promise<SafeResult<string>> => {
		try {
			const session = await prisma.session.create({
				data: {
					user: {
						connect: {
							id: user.id
						}
					},
					expires: secs(settings.expires)
				}
			});

			return {
				ok: true,
				data: session.id
			};
		} catch (err) {
			return {
				ok: false,
				error: 'Failed to create session.'
			};
		}
	};

	const getSession = async (
		sessionId: string,
		settings: Settings
	): Promise<Session | undefined | null> => {
		try {
			const session = await prisma.session.findUnique({
				where: {
					id: sessionId
				},
				include: {
					user: true
				}
			});

			if (!session) {
				return null;
			}

			if (session.expires < new Date()) {
				return null;
			}

			return {
				user: {
					id: session.userId,
					name: session.user.name,
					email: session.user.email,
					picture: session.user.picture
				},
				expires: secs(settings.expires),
				issuedAt: session.issuedAt
			};
		} catch (err) {
			return null;
		}
	};

	const deleteSession = async (sessionId: string): Promise<boolean> => {
		try {
			await prisma.session.delete({
				where: {
					id: sessionId
				}
			});

			return true;
		} catch (err) {
			return false;
		}
	};

	return {
		type,
		handleAccount,
		createSession,
		getSession,
		deleteSession
	};
};

export default Prisma;
