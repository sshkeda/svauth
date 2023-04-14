import type { OAuthProvider, SafeResult, User } from '$lib';
import { z } from 'zod';

interface DiscordConfig {
	clientId: string;
	clientSecret: string;
}

const discordUserSchema = z.object({
	id: z.string(),
	username: z.string(),
	avatar: z.string().nullable(),
	discriminator: z.string(),
	email: z.string()
});

const clientCredentialsSchema = z.object({
	access_token: z.string()
});

const Discord = ({ clientId, clientSecret }: DiscordConfig): OAuthProvider => {
	const name = 'discord';
	const scope = 'email identify';
	const authorizationEndpoint = 'https://discord.com/api/oauth2/authorize';
	const exchangeEndpoint = 'https://discord.com/api/oauth2/token';

	async function getUser(exchangeResponse: unknown): Promise<SafeResult<User>> {
		try {
			const clientCredentials = clientCredentialsSchema.safeParse(exchangeResponse);

			if (!clientCredentials.success)
				return {
					ok: false,
					error: 'Invalid token response.'
				};

			const accessToken = clientCredentials.data.access_token;

			const userResponse = await fetch('https://discord.com/api/users/@me', {
				headers: {
					Authorization: `Bearer ${accessToken}`
				}
			});

			if (!userResponse.ok) {
				return {
					ok: false,
					error: 'Failed to fetch discord user info.'
				};
			}

			const userJSON = (await userResponse.json()) as unknown;

			const discordUser = discordUserSchema.safeParse(userJSON);

			if (!discordUser.success)
				return {
					ok: false,
					error: 'Failed to parse discord user info.'
				};
			const { id, email, username, avatar, discriminator } = discordUser.data;

			const user = {
				id,
				email,
				name: username,
				picture: ''
			};

			if (!avatar) {
				const defaultAvatarNumber = parseInt(discriminator) % 5;
				user.picture = `https://cdn.discordapp.com/embed/avatars/${defaultAvatarNumber}.png`;
			} else {
				const format = avatar.startsWith('a_') ? 'gif' : 'png';
				user.picture = `https://cdn.discordapp.com/avatars/${id}/${avatar}.${format}`;
			}

			return {
				ok: true,
				data: user
			};
		} catch (err) {
			return {
				ok: false,
				error: 'Failed to fetch discord user info.'
			};
		}
	}

	return {
		name,
		clientId,
		clientSecret,
		scope,
		authorizationEndpoint,
		exchangeEndpoint,
		getUser
	};
};

export default Discord;
