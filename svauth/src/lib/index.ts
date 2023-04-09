import z from 'zod';
import { env } from '$env/dynamic/private';
import { env as publicEnv } from '$env/dynamic/public';
import { text, type Handle } from '@sveltejs/kit';
import { base } from '$app/paths';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const envSchema = z.object({
	SVAUTH_SECRET: z.string()
});

const { SVAUTH_SECRET } = envSchema.parse(env);

const publicEnvSchema = z.object({
	PUBLIC_SVAUTH_PREFIX: z.string().default('/auth')
});

const { PUBLIC_SVAUTH_PREFIX: SVAUTH_PREFIX } = publicEnvSchema.parse(publicEnv);

const schema = z
	.object({
		action: z.literal('signIn'),
		body: z.object({
			providerId: z.string()
		})
	})
	.or(
		z.object({
			action: z.literal('signOut'),
			body: z.object({}).default({})
		})
	);

const userSchema = z.object({
	id: z.string(),
	name: z.string(),
	email: z.string(),
	picture: z.string()
});

export type User = z.infer<typeof userSchema>;

const sessionSchema = z.object({
	user: userSchema,
	expires: z.number().transform((date) => new Date(date))
});

export type Session = z.infer<typeof sessionSchema>;

export interface OAuthProvider extends Provider {
	scope: string;
	authorizationEndpoint: string;
	tokenEndpoint: string;
	nonce?: boolean;
}

export interface Provider {
	clientId: string;
	clientSecret: string;
	name: string;
}

/**
 * @param {maxAge} maxAge maximum age of session in milliseconds. Defaults to 30 days.
 */
interface SvauthOptions {
	providers: Provider[];
	redirects?: {
		signIn?: string;
		signOut?: string;
	};
	maxAge?: number;
}

const Svauth = (options: SvauthOptions): Handle => {
	const maxAge = options.maxAge || 30 * 24 * 60 * 60 * 1000;

	const providers = Object.fromEntries(
		options.providers.map((provider) => [provider.name, provider])
	);

	return (async ({ event, resolve }) => {
		const origin = event.url.origin;

		const getRedirectUrl = (optionsUrl: string | undefined) => {
			if (optionsUrl) {
				try {
					return new URL(optionsUrl).toString();
				} catch (err) {
					return `${origin}${base}${optionsUrl}`;
				}
			} else {
				return `${origin}${base}/`;
			}
		};

		if (event.url.pathname.startsWith(SVAUTH_PREFIX)) {
			if (event.request.method === 'POST') {
				const json = (await event.request.json()) as unknown;
				const parsedBody = schema.safeParse(json);

				if (!parsedBody.success) return new Response('Invalid Request.', { status: 400 });

				const { action, body } = parsedBody.data;

				if (action === 'signIn') {
					const { providerId } = body;

					const config = providers[providerId] as OAuthProvider | undefined;
					if (!config) return new Response('Invalid provider.', { status: 400 });

					const authorizationEndpoint = new URL(config.authorizationEndpoint);

					authorizationEndpoint.searchParams.set(
						'redirect_uri',
						`${origin}${base}${SVAUTH_PREFIX}/callback/${providerId}`
					);
					authorizationEndpoint.searchParams.set('client_id', config.clientId);
					authorizationEndpoint.searchParams.set('response_type', 'code');
					authorizationEndpoint.searchParams.set('scope', config.scope);
					if (config.nonce)
						authorizationEndpoint.searchParams.set('nonce', crypto.randomBytes(32).toString('hex'));

					return text(authorizationEndpoint.toString());
				} else if (action === 'signOut') {
					const redirectUrl = getRedirectUrl(options.redirects?.signOut);
					return new Response(redirectUrl, {
						headers: {
							'Set-Cookie': 'SVAUTH_SESSION=; Path=/; Max-Age=0'
						}
					});
				}
			} else if (event.request.method === 'GET') {
				const path = event.url.pathname.slice(`${base}${SVAUTH_PREFIX}`.length);
				const eventPath = path.split('/');
				const action = eventPath[1];

				if (action === 'callback') {
					const providerId = eventPath[2];
					const config = providers[providerId] as OAuthProvider | undefined;

					if (!config) return new Response('Invalid provider.', { status: 404 });

					const code = event.url.searchParams.get('code');

					if (!code) {
						return new Response('No authorization code found.', { status: 404 });
					}

					const tokenEndpoint = new URL(config.tokenEndpoint);

					const tokenBody = new URLSearchParams();

					tokenBody.set('client_id', config.clientId);
					tokenBody.set('client_secret', config.clientSecret);
					tokenBody.set('grant_type', 'authorization_code');
					tokenBody.set('code', code);
					tokenBody.set('redirect_uri', `${origin}${base}${SVAUTH_PREFIX}/callback/${providerId}`);

					const tokenResponse = await fetch(tokenEndpoint.toString(), {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: tokenBody
					});

					if (!tokenResponse.ok)
						return new Response('Problem with given authorization code.', { status: 404 });

					const tokenJson = (await tokenResponse.json()) as unknown;

					const getUser = async () => {
						if (providerId === 'google') {
							const tokenSchema = z.object({
								id_token: z.string()
							});

							const parsedToken = tokenSchema.safeParse(tokenJson);

							if (!parsedToken.success) return new Response('No Id token found.', { status: 404 });

							const { id_token } = parsedToken.data;
							const decodedToken = jwt.decode(id_token);

							if (!decodedToken || typeof decodedToken === 'string')
								return new Response('Failed to parse JWT token.', { status: 404 });

							decodedToken.id = decodedToken.sub;

							const parsedUser = userSchema.safeParse(decodedToken);

							if (!parsedUser.success)
								return new Response('Failed to parse name, email, and picture out of JWT token.', {
									status: 404
								});

							return parsedUser.data;
						} else {
							// Discord
							const discordSchema = z.object({
								access_token: z.string(),
								token_type: z.string(),
								expires_in: z.number(),
								refresh_token: z.string(),
								scope: z.string()
							});

							const token = discordSchema.safeParse(tokenJson);

							if (!token.success) return new Response('Invalid token response.', { status: 404 });

							const userResponse = await fetch('https://discord.com/api/users/@me', {
								headers: {
									Authorization: `Bearer ${token.data.access_token}`
								}
							});

							if (!userResponse.ok)
								return new Response('Problem with accessing current authorization info.', {
									status: 404
								});

							const userJson = (await userResponse.json()) as unknown;

							const discordUserSchema = z.object({
								id: z.string(),
								username: z.string(),
								avatar: z.string().nullable(),
								discriminator: z.string(),
								email: z.string()
							});

							const parsedUser = discordUserSchema.safeParse(userJson);

							if (!parsedUser.success)
								return new Response('Failed to parse discord user info.', {
									status: 404
								});

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

					const user = await getUser();

					const expiryDate = new Date();
					expiryDate.setDate(expiryDate.getDate() + 30);

					const session = {
						expires: expiryDate.getTime(),
						user
					};

					const encodedToken = jwt.sign(session, SVAUTH_SECRET);
					return new Response('signIn', {
						status: 301,
						headers: {
							Location: options?.redirects?.signIn || '/',
							'Set-Cookie': `SVAUTH_SESSION=${encodedToken}; Path=/; Expires=${expiryDate.toUTCString()}`
						}
					});
				}
			}
			return new Response('Svauth action not found.', {
				status: 404
			});
		}

		const getSession = () => {
			const sessionCookie = event.cookies.get('SVAUTH_SESSION');
			if (!sessionCookie) return undefined;
			try {
				const unparsedSession = jwt.verify(sessionCookie, SVAUTH_SECRET);
				const session = sessionSchema.parse(unparsedSession);
				if (session.expires < new Date()) {
					event.cookies.delete('SVAUTH_SESSION');
					return null;
				}
				const newExpiryDate = new Date().getTime() + maxAge;
				session.expires = new Date(newExpiryDate);
				const encodedToken = jwt.sign(
					{
						expires: newExpiryDate,
						user: session.user
					},
					SVAUTH_SECRET
				);
				event.cookies.set('SVAUTH_SESSION', encodedToken, {
					path: '/',
					expires: new Date(newExpiryDate)
				});

				return session;
			} catch (error) {
				event.cookies.delete('SVAUTH_SESSION');
				return null;
			}
		};

		event.locals.getSession = () => getSession();
		const response = await resolve(event);
		return response;
	}) satisfies Handle;
};

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace App {
		interface Locals {
			getSession(): Session | undefined | null;
		}
	}
}

export default Svauth;
