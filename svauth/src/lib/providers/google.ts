import type { OAuthProvider, User } from '$lib';
import { z } from 'zod';
import jwt from 'jsonwebtoken';

interface GoogleConfig {
	clientId: string;
	clientSecret: string;
}

const Google = ({ clientId, clientSecret }: GoogleConfig): OAuthProvider => {
	return {
		name: 'google',
		clientId,
		clientSecret,
		scope: 'openid email profile',
		authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
		tokenEndpoint: 'https://oauth2.googleapis.com/token',
		nonce: true,
		getUser: async (tokenJson: unknown) => {
			const tokenSchema = z.object({
				id_token: z.string()
			});

			const parsedToken = tokenSchema.safeParse(tokenJson);

			if (!parsedToken.success) throw new Error('No Id token found.');

			const { id_token } = parsedToken.data;
			const decodedToken = jwt.decode(id_token);

			if (!decodedToken || typeof decodedToken === 'string')
				throw new Error('Failed to parse JWT token.');

			decodedToken.id = decodedToken.sub;

			const googleUserSchema = z.object({
				id: z.string(),
				name: z.string(),
				email: z.string(),
				picture: z.string()
			});

			const parsedUser = googleUserSchema.safeParse(decodedToken);

			if (!parsedUser.success)
				throw new Error('Failed to parse name, email, and picture out of JWT token.');

			return parsedUser.data;
		}
	};
};

export default Google;
