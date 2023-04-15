import z from 'zod';
import { env } from '$env/dynamic/private';
import { env as publicEnv } from '$env/dynamic/public';
import type { Handle, RequestEvent } from '@sveltejs/kit';
import { base } from '$app/paths';
import * as jose from 'jose';
import { DEV } from 'esm-env';
import type { SafeResult } from '$lib/utils/types';
import handlePOST from './handler/handlePOST';
import handleGET from './handler/handleGET';

const envSchema = z.object({
	SVAUTH_SECRET: z.string().transform((secret) => {
		return jose.base64url.decode(secret);
	}),
	SVAUTH_URL: z.string().optional(),
	VERCEL_URL: z.string().optional()
});

const { SVAUTH_SECRET, VERCEL_URL, SVAUTH_URL } = envSchema.parse(env);

const getOrigin = () => {
	if (DEV) {
		return `http://localhost:5173${base}`;
	}

	if (VERCEL_URL) {
		return `https://${VERCEL_URL}${base}`;
	}

	if (!SVAUTH_URL) throw new Error('SVAUTH_URL is not defined.');

	return SVAUTH_URL;
};

const userSchema = z.object({
	id: z.string(),
	name: z.string(),
	email: z.string(),
	picture: z.string()
});

export type User = z.infer<typeof userSchema>;

const sessionTokenSchema = z.object({
	user: userSchema,
	iat: z.number(),
	exp: z.number()
});

export type SessionToken = z.infer<typeof sessionTokenSchema>;

const sessionSchema = z
	.object({
		user: userSchema,
		iat: z.number(),
		exp: z.number()
	})
	.transform((session) => {
		return {
			user: session.user,
			expires: new Date(session.exp * 1000),
			issuedAt: new Date(session.iat * 1000)
		};
	});

export type Session = z.infer<typeof sessionSchema>;

export interface OAuthProvider extends Provider {
	scope: string;
	authorizationEndpoint: string;
	exchangeEndpoint: string;
	nonce?: boolean;
	state?: boolean;
	jwksEndpoint?: string;
	verifyToken?: (token: string) => Promise<SafeResult<jose.JWTPayload>>;
	parseUser?: (jwt: jose.JWTPayload) => Promise<SafeResult<User>>;
	getUser: (exchangeResponse: unknown) => Promise<SafeResult<User>>;
}

/**
 * @param {expires} expires maximum age of session in milliseconds. Defaults to 30 days.
 */
interface SvauthOptions {
	providers: Provider[];
	expires?: number | string;
}

const providerSchema = z
	.object({
		clientId: z.string(),
		clientSecret: z.string(),
		name: z.string()
	})
	.passthrough();

export type Provider = z.infer<typeof providerSchema>;

const expiresSchema = z.number().or(
	z
		.number()
		.or(
			z.string().regex(
				// https://github.com/panva/jose/blob/main/src/lib/secs.ts
				/^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i
			)
		)
		.default('30d')
);

const adapterSchema = z.object({
	url: z.string(),
	secret: z.string()
});

const strategySchema = z.union([z.literal('jwt'), z.literal('adapter')]);

const settingsSchema = z
	.object({
		providers: z.array(providerSchema),
		expires: expiresSchema,
		adapter: adapterSchema.optional(),
		strategy: strategySchema.optional()
	})
	.transform((settings) => {
		return {
			providers: Object.fromEntries(
				settings.providers.map((provider) => [provider.name, provider])
			),
			expires: settings.expires,
			adapter: settings.adapter,
			strategy: settings.strategy || (settings.adapter ? 'adapter' : 'jwt'),
			prefix: publicEnv.PUBLIC_SVAUTH_PREFIX || '/auth',
			origin: getOrigin(),
			secret: SVAUTH_SECRET
		};
	});

export type Settings = z.infer<typeof settingsSchema>;

export const getSession = async (event: RequestEvent, expires: number | string) => {
	const sessionCookie = event.cookies.get('SVAUTH_SESSION');
	if (!sessionCookie) return undefined;
	try {
		const unparsedTokenSession = await jose.jwtDecrypt(sessionCookie, SVAUTH_SECRET);

		const tokenSession = sessionTokenSchema.parse(unparsedTokenSession.payload);

		const encodedToken = await encryptJWT(tokenSession, expires);

		event.cookies.set('SVAUTH_SESSION', encodedToken, {
			path: '/'
		});

		const session = sessionSchema.parse(tokenSession);

		return session;
	} catch (error) {
		event.cookies.delete('SVAUTH_SESSION');
		return null;
	}
};

const encryptJWT = (payload: jose.JWTPayload, expires: string | number) =>
	new jose.EncryptJWT(payload)
		.setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
		.setExpirationTime(expires)
		.encrypt(SVAUTH_SECRET);

const Svauth = (options: SvauthOptions): Handle => {
	const settings = settingsSchema.parse(options);

	return (async ({ event, resolve }) => {
		if (event.url.pathname.startsWith(settings.prefix)) {
			if (event.request.method === 'POST') {
				return await handlePOST(event);
			} else if (event.request.method === 'GET') {
				return await handleGET(event, settings);
			}
			return new Response(`Invalid request method.`, {
				status: 405
			});
		}

		event.locals.getSession = () => getSession(event, settings.expires);
		const response = await resolve(event);
		return response;
	}) satisfies Handle;
};

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace App {
		interface Locals {
			getSession(): Promise<Session | undefined | null>;
		}
		interface PageData {
			session: Session | undefined | null;
		}
	}
}

export default Svauth;
