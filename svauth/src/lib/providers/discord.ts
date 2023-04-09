import type { OAuthProvider, User } from '$lib';
import { z } from 'zod';

interface DiscordConfig {
	clientId: string;
	clientSecret: string;
}

const Discord = ({ clientId, clientSecret }: DiscordConfig): OAuthProvider => {
	return {
		name: 'discord',
		clientId,
		clientSecret,
		scope: 'email identify',
		authorizationEndpoint: 'https://discord.com/api/oauth2/authorize',
		tokenEndpoint: 'https://discord.com/api/oauth2/token',
		getUser: async (tokenJson: unknown) => {
			const discordSchema = z.object({
				access_token: z.string()
			});

			const token = discordSchema.safeParse(tokenJson);

			if (!token.success) throw new Error('Invalid token response.');

			const userResponse = await fetch('https://discord.com/api/users/@me', {
				headers: {
					Authorization: `Bearer ${token.data.access_token}`
				}
			});

			if (!userResponse.ok) throw new Error('Problem with accessing current authorization info.');

			const userJson = (await userResponse.json()) as unknown;

			const discordUserSchema = z.object({
				id: z.string(),
				username: z.string(),
				avatar: z.string().nullable(),
				discriminator: z.string(),
				email: z.string()
			});

			const parsedUser = discordUserSchema.safeParse(userJson);

			if (!parsedUser.success) throw new Error('Failed to parse discord user info.');

			const discorduser = parsedUser.data;
			const user = {
				id: discorduser.id,
				email: discorduser.email,
				name: discorduser.username,
				picture: ''
			} satisfies User;

			if (!discorduser.avatar) {
				const defaultAvatarNumber = parseInt(discorduser.discriminator) % 5;
				user.picture = `https://cdn.discordapp.com/embed/avatars/${defaultAvatarNumber}.png`;
			} else {
				const format = discorduser.avatar.startsWith('a_') ? 'gif' : 'png';
				user.picture = `https://cdn.discordapp.com/avatars/${discorduser.id}/${discorduser.avatar}.${format}`;
			}
			return user;
		}
	};
};

export default Discord;
