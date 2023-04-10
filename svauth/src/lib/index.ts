import z from 'zod';
import { env } from '$env/dynamic/private';
import { env as publicEnv } from '$env/dynamic/public';
import { text, type Handle, type RequestEvent, json } from '@sveltejs/kit';
import { base } from '$app/paths';
import crypto from 'crypto';
import * as jose from 'jose';
import { DEV } from 'esm-env';

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
const origin = getOrigin();

const publicEnvSchema = z.object({
	PUBLIC_SVAUTH_PREFIX: z.string().default('/auth')
});

const { PUBLIC_SVAUTH_PREFIX: SVAUTH_PREFIX } = publicEnvSchema.parse(publicEnv);

const postBodySchema = z
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

interface OKResult<T> {
	ok: true;
	data: T;
}

interface ErrorResult {
	ok: false;
	error: string;
}

type SafeResult<T> = OKResult<T> | ErrorResult;

export interface OAuthProvider extends Provider {
	scope: string;
	authorizationEndpoint: string;
	tokenEndpoint: string;
	nonce?: boolean;
	jwksEndpoint?: string;
	verifyToken: (token: string) => Promise<SafeResult<jose.JWTPayload>>;
	parseUser: (jwt: jose.JWTPayload) => Promise<SafeResult<User>>;
	parseToken: (tokenJson: unknown) => Promise<SafeResult<jose.JWTPayload>>;
}

export interface Provider {
	clientId: string;
	clientSecret: string;
	name: string;
}

interface ProvidersObject {
	[providerId: string]: Provider;
}

/**
 * @param {expires} expires maximum age of session in milliseconds. Defaults to 30 days.
 */
interface SvauthOptions {
	providers: Provider[];
	redirects?: {
		signIn?: string;
		signOut?: string;
	};
	expires?: number | string;
}

const settingsSchema = z.object({
	providers: z.array(
		z
			.object({
				clientId: z.string(),
				clientSecret: z.string(),
				name: z.string()
			})
			.passthrough()
	),
	redirects: z
		.object({
			signIn: z.string().optional(),
			signOut: z.string().optional()
		})
		.optional(),
	expires: z
		.number()
		.or(
			z.string().regex(
				// https://github.com/panva/jose/blob/main/src/lib/secs.ts
				/^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i
			)
		)
		.default('30d')
});

type Settings = z.infer<typeof settingsSchema>;

const getAuthorizationEndpoint = (config: OAuthProvider) => {
	const authorizationEndpoint = new URL(config.authorizationEndpoint);

	authorizationEndpoint.searchParams.set(
		'redirect_uri',
		`${origin}${base}${SVAUTH_PREFIX}/callback/${config.name}`
	);
	authorizationEndpoint.searchParams.set('client_id', config.clientId);
	authorizationEndpoint.searchParams.set('response_type', 'code');
	authorizationEndpoint.searchParams.set('scope', config.scope);
	if (config.nonce)
		authorizationEndpoint.searchParams.set('nonce', crypto.randomBytes(32).toString('hex'));

	return authorizationEndpoint.toString();
};

const getSession = async (event: RequestEvent, expires: number | string) => {
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

const createSession = async (user: User, expires: number | string) => {
	const session = {
		user
	};

	const encodedToken = await new jose.EncryptJWT(session)
		.setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
		.setIssuedAt()
		.setExpirationTime(expires)
		.encrypt(SVAUTH_SECRET);

	return encodedToken;
};

const Svauth = (options: SvauthOptions): Handle => {
	const settings = settingsSchema.parse(options);

	const providers = Object.fromEntries(
		options.providers.map((provider) => [provider.name, provider])
	) satisfies ProvidersObject;

	return (async ({ event, resolve }) => {
		if (event.url.pathname.startsWith(SVAUTH_PREFIX)) {
			if (event.request.method === 'POST') {
				return await handlePOST(settings, event, providers);
			} else if (event.request.method === 'GET') {
				return await handleGET(settings, event, providers);
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

const handlePOST = async (settings: Settings, event: RequestEvent, providers: ProvidersObject) => {
	const postBody = (await event.request.json()) as unknown;
	const parsedBody = postBodySchema.safeParse(postBody);

	if (!parsedBody.success) return new Response('Invalid Request.', { status: 400 });

	const { action, body } = parsedBody.data;

	if (action === 'signIn') {
		const { providerId } = body;
		const config = providers[providerId] as OAuthProvider | undefined;
		if (!config) return new Response('Invalid provider.', { status: 400 });
		return text(getAuthorizationEndpoint(config));
	} else if (action === 'signOut') {
		const redirectUrl = settings.redirects?.signOut || '/';
		return new Response(redirectUrl, {
			headers: {
				'Set-Cookie': 'SVAUTH_SESSION=; Path=/; Max-Age=0'
			}
		});
	} else {
		return new Response('Invalid action.', { status: 400 });
	}
};

const getToken = async (config: OAuthProvider, code: string) => {
	try {
		const tokenEndpoint = new URL(config.tokenEndpoint);

		const tokenBody = new URLSearchParams();

		tokenBody.set('client_id', config.clientId);
		tokenBody.set('client_secret', config.clientSecret);
		tokenBody.set('grant_type', 'authorization_code');
		tokenBody.set('code', code);
		tokenBody.set('redirect_uri', `${origin}${base}${SVAUTH_PREFIX}/callback/${config.name}`);

		const tokenResponse = await fetch(tokenEndpoint.toString(), {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: tokenBody
		});

		if (!tokenResponse.ok) return new Response('Problem with token response.', { status: 404 });

		return tokenResponse.json() as unknown;
	} catch (err) {
		return new Response('Problem with given authorization code.', { status: 404 });
	}
};

const handleGET = async (settings: Settings, event: RequestEvent, providers: ProvidersObject) => {
	const path = event.url.pathname.slice(`${base}${SVAUTH_PREFIX}`.length);
	const eventPath = path.split('/');
	const action = eventPath[1];

	if (action === 'session') {
		const session = await getSession(event, settings.expires);
		return json(session);
	}

	if (action !== 'callback') {
		return new Response('Invalid Svauth action.', { status: 404 });
	}

	const providerId = eventPath[2];

	if (providerId === 'token') {
		const token = event.url.searchParams.get('token');
		const providerId = event.url.searchParams.get('provider');

		if (!token || !providerId) {
			return new Response('Missing parameters.', { status: 404 });
		}

		const config = providers[providerId] as OAuthProvider | undefined;
		if (!config) return new Response('Invalid provider.', { status: 404 });

		const tokenResponse = await config.verifyToken(token);

		if (!tokenResponse.ok) return new Response(tokenResponse.error, { status: 404 });

		const decodedToken = tokenResponse.data;

		const user = await config.parseUser(decodedToken);

		if (!user.ok) return new Response(user.error, { status: 404 });

		const encodedToken = await createSession(user.data, settings.expires);

		const redirectUrl = settings.redirects?.signIn || '/';

		return new Response('signIn', {
			status: 301,
			headers: {
				Location: redirectUrl,
				'Set-Cookie': `SVAUTH_SESSION=${encodedToken}; Path=/;`
			}
		});
	}

	const config = providers[providerId] as OAuthProvider | undefined;

	if (!config) return new Response('Invalid provider.', { status: 404 });

	const code = event.url.searchParams.get('code');

	if (!code) {
		return new Response('No authorization code found.', { status: 404 });
	}

	const token = await getToken(config, code);

	if (token instanceof Response) return token;

	const userJWT = await config.parseToken(token);

	if (!userJWT.ok) return new Response(userJWT.error, { status: 404 });

	const user = await config.parseUser(userJWT.data);

	if (!user.ok) return new Response(user.error, { status: 404 });

	const encodedToken = await createSession(user.data, settings.expires);

	const redirectUrl = settings.redirects?.signIn || '/';

	return new Response('signIn', {
		status: 301,
		headers: {
			Location: redirectUrl,
			'Set-Cookie': `SVAUTH_SESSION=${encodedToken}; Path=/;`
		}
	});
};

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace App {
		interface Locals {
			getSession(): Promise<Session | undefined | null>;
		}
	}
}

export default Svauth;
