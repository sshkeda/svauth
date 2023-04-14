import type { OAuthProvider, SafeResult, User } from '$lib';
import { z } from 'zod';

interface GitHubConfig {
	clientId: string;
	clientSecret: string;
}

const tokenSchema = z.object({
	access_token: z.string()
});

const gitHubUserSchema = z
	.object({
		id: z.number(),
		avatar_url: z.string().url(),
		name: z.string()
	})
	.transform((user) => ({
		id: user.id.toString(),
		picture: user.avatar_url,
		name: user.name,
		email: ''
	}));

const gitHubEmailSchema = z
	.array(
		z.object({
			email: z.string().email(),
			primary: z.boolean()
		})
	)
	.nonempty();

const GitHub = ({ clientId, clientSecret }: GitHubConfig): OAuthProvider => {
	const name = 'github';
	const scope = 'read:user user:email';
	const state = true;
	const authorizationEndpoint = 'https://github.com/login/oauth/authorize';
	const exchangeEndpoint = 'https://github.com/login/oauth/access_token';

	const getUser = async (exchangeResponse: unknown): Promise<SafeResult<User>> => {
		try {
			const { access_token: accessToken } = tokenSchema.parse(exchangeResponse);
			const userResponse = await fetch('https://api.github.com/user', {
				headers: {
					Authorization: `Bearer ${accessToken}`
				}
			});

			if (!userResponse.ok) {
				return {
					ok: false,
					error: 'Failed to fetch user info.'
				};
			}

			const userJSON = (await userResponse.json()) as unknown;
			const user = gitHubUserSchema.parse(userJSON);

			const emailsResponse = await fetch('https://api.github.com/user/emails', {
				headers: {
					Authorization: `Bearer ${accessToken}`
				}
			});

			if (!emailsResponse.ok) {
				return {
					ok: false,
					error: 'Failed to fetch user email.'
				};
			}

			const emailsJSON = (await emailsResponse.json()) as unknown;
			const emails = gitHubEmailSchema.parse(emailsJSON);
			const email = emails.find((email) => email.primary)?.email || emails[0].email;

			user.email = email;

			return {
				ok: true,
				data: user
			};
		} catch (err) {
			return {
				ok: false,
				error: 'Failed to parse user info from token.'
			};
		}
	};

	return {
		clientId,
		clientSecret,
		name,
		scope,
		state,
		authorizationEndpoint,
		exchangeEndpoint,
		getUser
	};
};

export default GitHub;
