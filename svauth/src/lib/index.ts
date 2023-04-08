import z from 'zod';
import { env } from '$env/dynamic/private';
import { env as publicEnv } from '$env/dynamic/public';
import { text, type Handle } from '@sveltejs/kit';
import { base } from '$app/paths';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const envSchema = z.object({
	GOOGLE_CLIENT_SECRET: z.string(),
	GOOGLE_CLIENT_ID: z.string(),
	SVAUTH_SECRET: z.string()
});

const { GOOGLE_CLIENT_SECRET, GOOGLE_CLIENT_ID, SVAUTH_SECRET } = envSchema.parse(env);

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

const tokenSchema = z.object({
	access_token: z.string(),
	expires_in: z.number(),
	scope: z.string(),
	token_type: z.string(),
	id_token: z.string()
});

const userSchema = z.object({
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

export interface Provider {
	client_id: string;
	client_secret: string;
}

/**
 * @param {maxAge} maxAge maximum age of session in milliseconds
 */
interface SvauthOptions {
	providers?: Provider[];
	redirects?: {
		signIn?: string;
		signOut?: string;
	};
	maxAge?: number;
}

const Svauth = (options: SvauthOptions): Handle => {
	const maxAge = options.maxAge || 30 * 24 * 60 * 60 * 1000;
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

					if (providerId === 'google') {
						const nonce = crypto.randomBytes(32).toString('hex');

						const authorization_endpoint = new URL('https://accounts.google.com/o/oauth2/v2/auth');

						authorization_endpoint.searchParams.set(
							'redirect_uri',
							`${origin}${base}${SVAUTH_PREFIX}/redirect/google`
						);
						authorization_endpoint.searchParams.set('client_id', GOOGLE_CLIENT_ID);
						authorization_endpoint.searchParams.set('response_type', 'code');
						authorization_endpoint.searchParams.set('scope', 'openid email profile');
						authorization_endpoint.searchParams.set('nonce', nonce);

						return text(authorization_endpoint.toString());
					}
				} else if (action === 'signOut') {
					const redirectUrl = getRedirectUrl(options.redirects?.signOut);
					return new Response(redirectUrl, {
						headers: {
							'Set-Cookie': 'SVAUTH_SESSION=; Path=/; Max-Age=0'
						}
					});
				}
			} else if (event.request.method === 'GET') {
				const path = event.url.pathname.split('/');
				const action = path[2];

				if (action === 'redirect') {
					const provider = path[3];
					if (provider === 'google') {
						const code = event.url.searchParams.get('code');
						if (!code) {
							return new Response('No authorization code found.', { status: 404 });
						}

						const tokenEndpoint = new URL('https://oauth2.googleapis.com/token');

						const tokenBody = new URLSearchParams();

						tokenBody.set('code', code);
						tokenBody.set('client_id', GOOGLE_CLIENT_ID);
						tokenBody.set('client_secret', GOOGLE_CLIENT_SECRET);
						tokenBody.set('redirect_uri', `${origin}${base}${SVAUTH_PREFIX}/redirect/google`);
						tokenBody.set('grant_type', 'authorization_code');

						const tokenResponse = await fetch(tokenEndpoint.toString(), {
							method: 'POST',
							headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
							body: tokenBody
						});

						if (!tokenResponse.ok)
							return new Response('Problem with given authorization code.', { status: 404 });

						const tokenJson = (await tokenResponse.json()) as unknown;

						const token = tokenSchema.safeParse(tokenJson);

						if (!token.success) return new Response('Invalid token response.', { status: 404 });

						const decodedToken = jwt.decode(token.data.id_token);

						if (!decodedToken) return new Response('Failed to parse JWT token.', { status: 404 });

						const user = userSchema.safeParse(decodedToken);

						if (!user.success)
							return new Response('Failed to parse name, email, and picture out of JWT token.', {
								status: 404
							});

						const expiryDate = new Date();
						expiryDate.setDate(expiryDate.getDate() + 30);

						const session = {
							expires: expiryDate.getTime(),
							user: user.data
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
