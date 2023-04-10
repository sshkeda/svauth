import type { OAuthProvider } from '$lib';
import { z } from 'zod';
import type * as jose from 'jose';

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

/**
 *
 * Svauth Discord Provider
 *
 * @see https://discord.com/developers/docs/topics/oauth2
 *
 */
const Discord = ({ clientId, clientSecret }: DiscordConfig): OAuthProvider => {
	return {
		name: 'discord',
		clientId,
		clientSecret,
		scope: 'email identify',
		authorizationEndpoint: 'https://discord.com/api/oauth2/authorize',
		tokenEndpoint: 'https://discord.com/api/oauth2/token',
		verifyToken: async function (token: string) {
			const userResponse = await fetch('https://discord.com/api/users/@me', {
				headers: {
					Authorization: `Bearer ${token}`
				}
			});

			if (!userResponse.ok) {
				return {
					ok: false,
					error: 'Failed to fetch discord user info.'
				};
			}

			const userJson = (await userResponse.json()) as unknown;

			const parsedDiscordUser = discordUserSchema.safeParse(userJson);

			if (!parsedDiscordUser.success)
				return {
					ok: false,
					error: 'Failed to parse discord user info.'
				};

			return {
				ok: true,
				data: parsedDiscordUser.data
			};
		},
		parseToken: async function (tokenJson: unknown) {
			const tokenSchema = z.object({
				access_token: z.string()
			});

			const token = tokenSchema.safeParse(tokenJson);

			if (!token.success)
				return {
					ok: false,
					error: 'Invalid token response.'
				};

			return this.verifyToken(token.data.access_token);
		},
		parseUser: async (jwt: jose.JWTPayload) => {
			const discordUser = jwt as z.infer<typeof discordUserSchema>;
			const user = {
				id: discordUser.id,
				email: discordUser.email,
				name: discordUser.username,
				picture: ''
			};

			if (!discordUser.avatar) {
				const defaultAvatarNumber = parseInt(discordUser.discriminator) % 5;
				user.picture = `https://cdn.discordapp.com/embed/avatars/${defaultAvatarNumber}.png`;
			} else {
				const format = discordUser.avatar.startsWith('a_') ? 'gif' : 'png';
				user.picture = `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.${format}`;
			}

			return {
				ok: true,
				data: user
			};
		}
	};
};

export default Discord;
