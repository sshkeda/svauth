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
	PUBLIC_SVAUTH_PREFIX: z.string().default('/auth'),
	PUBLIC_SVAUTH_URL: z.string().url().default('http://localhost:5173')
});

const { PUBLIC_SVAUTH_PREFIX: SVAUTH_PREFIX, PUBLIC_SVAUTH_URL: SVAUTH_URL } =
	publicEnvSchema.parse(publicEnv);

const SVAUTH_PATH = SVAUTH_URL + base + SVAUTH_PREFIX;

export interface Provider {
	client_id: string;
	client_secret: string;
}

interface SvauthOptions {
	providers?: Provider[];
	redirects?: {
		signIn?: string;
		signOut?: string;
	};
}

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

const getSession = (sessionCookie: string | undefined) => {
	if (!sessionCookie) return undefined;
	try {
		return jwt.verify(sessionCookie, SVAUTH_SECRET) as jwt.JwtPayload;
	} catch (error) {
		return null;
	}
};

const Svauth = (options?: SvauthOptions): Handle =>
	(async ({ event, resolve }) => {
		if (event.url.pathname.startsWith(SVAUTH_PREFIX)) {
			if (event.request.method === 'POST') {
				const json = (await event.request.json()) as unknown;
				const { action, body } = schema.parse(json);

				if (action === 'signIn') {
					const { providerId } = body;

					if (providerId === 'google') {
						const nonce = crypto.randomBytes(32).toString('hex');

						const authorization_endpoint = new URL('https://accounts.google.com/o/oauth2/v2/auth');

						authorization_endpoint.searchParams.set(
							'redirect_uri',
							`${SVAUTH_PATH}/redirect/google`
						);
						authorization_endpoint.searchParams.set('client_id', GOOGLE_CLIENT_ID);
						authorization_endpoint.searchParams.set('response_type', 'code');
						authorization_endpoint.searchParams.set('scope', 'openid email profile');
						authorization_endpoint.searchParams.set('nonce', nonce);

						return text(authorization_endpoint.toString());
					}
				} else if (action === 'signOut') {
					event.cookies.delete('SVAUTH_SESSION');

					return new Response(options?.redirects?.signOut || '/', {
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
							return new Response('NO CODE', { status: 404 });
						}

						const tokenEndpoint = new URL('https://oauth2.googleapis.com/token');

						const tokenBody = new URLSearchParams();

						tokenBody.set('code', code);
						tokenBody.set('client_id', GOOGLE_CLIENT_ID);
						tokenBody.set('client_secret', GOOGLE_CLIENT_SECRET);
						tokenBody.set('redirect_uri', `${SVAUTH_PATH}/redirect/google`);
						tokenBody.set('grant_type', 'authorization_code');

						const tokenResponse = await fetch(tokenEndpoint.toString(), {
							method: 'POST',
							headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
							body: tokenBody
						});

						if (!tokenResponse.ok)
							return new Response('Problem with given authorization code.', { status: 404 });

						const tokenJson = (await tokenResponse.json()) as unknown;

						const token = tokenSchema.parse(tokenJson);

						const decodedToken = jwt.decode(token.id_token);

						if (!decodedToken) return new Response('Failed to parse JWT token.', { status: 404 });

						const maxAge = 60 * 60 * 24 * 30; // 30 days
						const encodedToken = jwt.sign(decodedToken, SVAUTH_SECRET);

						return new Response('signIn', {
							status: 301,
							headers: {
								Location: options?.redirects?.signIn || `${base}/`,
								'Set-Cookie': `SVAUTH_SESSION=${encodedToken}; Max-Age=${maxAge}; SameSite=Strict; Path=/;`
							}
						});
					}
				}
			}
			return new Response();
		}

		event.locals.getSession = () => getSession(event.cookies.get('SVAUTH_SESSION'));
		const response = await resolve(event);
		return response;
	}) satisfies Handle;

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace App {
		interface Locals {
			getSession(): jwt.JwtPayload | undefined | null;
		}
	}
}

export default Svauth;
