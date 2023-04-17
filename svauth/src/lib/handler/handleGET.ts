import { base } from '$app/paths';
import { getSession, type OAuthProvider, type Settings, type User } from '$lib';
import type { SafeResult } from '$lib/utils/types';
import { json, text, type RequestEvent } from '@sveltejs/kit';
import * as jose from 'jose';
import { z } from 'zod';
import crypto from 'crypto';
import { createId } from '@paralleldrive/cuid2';

const createSession = async (user: User, settings: Settings): Promise<SafeResult<string>> => {
	const session = {
		user
	};

	if (settings.adapter) {
		const sessionId = await settings.adapter.createSession(user, settings);
		if (!sessionId.ok) {
			return {
				ok: false,
				error: 'Problem with creating session.'
			};
		}

		return {
			ok: true,
			data: sessionId.data
		};
	}
	const encodedToken = await new jose.EncryptJWT(session)
		.setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
		.setIssuedAt()
		.setExpirationTime(settings.expires)
		.encrypt(settings.secret);

	return {
		ok: true,
		data: encodedToken
	};
};

const exchangeAuthorizationCode = async (
	code: string,
	config: OAuthProvider,
	settings: Settings
): Promise<SafeResult<unknown>> => {
	try {
		const exchangeEndpoint = new URL(config.exchangeEndpoint);

		const exchangeBody = new URLSearchParams();

		const { origin, prefix } = settings;

		exchangeBody.set('client_id', config.clientId);
		exchangeBody.set('client_secret', config.clientSecret);
		exchangeBody.set('grant_type', 'authorization_code');
		exchangeBody.set('code', code);
		exchangeBody.set('redirect_uri', `${origin}${base}${prefix}/callback/${config.name}`);

		const exchangeResponse = await fetch(exchangeEndpoint.toString(), {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
			body: exchangeBody
		});

		if (!exchangeResponse.ok) {
			return {
				ok: false,
				error: 'Problem with exchanging authorization code.'
			};
		}

		return {
			ok: true,
			data: (await exchangeResponse.json()) as unknown
		};
	} catch (err) {
		return {
			ok: false,
			error: 'Problem with exchanging authorization code.'
		};
	}
};

const eventPathSchema = z.union([
	z.tuple([z.literal('callback'), z.string()]),
	z.tuple([z.literal('session')]),
	z.tuple([z.literal('signin'), z.string()]),
	z.tuple([z.literal('client_id'), z.literal('google')])
]);

const handleGET = async (event: RequestEvent, settings: Settings) => {
	// + 1 to remove / from the beginning of the path
	const path = event.url.pathname.slice(`${base}${settings.prefix}`.length + 1);
	const eventPathArray = path.split('/');

	const eventPath = eventPathSchema.safeParse(eventPathArray);

	if (!eventPath.success) {
		return new Response('Invalid Svauth path.', { status: 404 });
	}

	const action = eventPath.data[0];

	if (action === 'session') {
		const session = await getSession(event, settings);
		return json({
			session
		});
	}

	if (action === 'client_id') {
		return text(settings.providers.google.clientId);
	}

	const provider = eventPath.data[1];

	if (action === 'signin') {
		const config = settings.providers[provider] as OAuthProvider | undefined;

		if (!config) return new Response('Invalid provider.', { status: 404 });

		const authorizationEndpoint = new URL(config.authorizationEndpoint);

		const { origin, prefix } = settings;
		authorizationEndpoint.searchParams.set(
			'redirect_uri',
			`${origin}${base}${prefix}/callback/${config.name}`
		);
		authorizationEndpoint.searchParams.set('client_id', config.clientId);
		authorizationEndpoint.searchParams.set('response_type', 'code');
		authorizationEndpoint.searchParams.set('scope', config.scope);
		if (config.nonce)
			authorizationEndpoint.searchParams.set('nonce', crypto.randomBytes(32).toString('hex'));

		if (config.state)
			authorizationEndpoint.searchParams.set('state', crypto.randomBytes(32).toString('hex'));

		return new Response(`Redirecting to ${provider} authorization endpoint.`, {
			status: 307,
			headers: {
				Location: authorizationEndpoint.toString()
			}
		});
	}

	let accountUser: SafeResult<User>;
	let config: OAuthProvider | undefined;

	if (provider === 'token') {
		const idToken = event.url.searchParams.get('token');
		const providerId = event.url.searchParams.get('provider');

		if (!idToken || !providerId) return new Response('Missing parameters.', { status: 404 });

		config = settings.providers[providerId] as OAuthProvider | undefined;
		if (!config) return new Response('Invalid provider.', { status: 404 });
		if (!config.verifyToken || !config.parseUser)
			return new Response('Provider does not support token verification.', { status: 404 });

		const jwt = await config.verifyToken(idToken);
		if (!jwt.ok) return new Response(jwt.error, { status: 404 });

		accountUser = await config.parseUser(jwt.data);
	} else {
		config = settings.providers[provider] as OAuthProvider | undefined;
		if (!config) return new Response('Invalid provider.', { status: 404 });

		const authorizationCode = event.url.searchParams.get('code');
		if (!authorizationCode) return new Response('No authorization code found.', { status: 404 });

		const exchangeResponse = await exchangeAuthorizationCode(authorizationCode, config, settings);
		if (!exchangeResponse.ok) return new Response(exchangeResponse.error, { status: 404 });

		accountUser = await config.getUser(exchangeResponse.data);
	}

	if (!accountUser.ok) return new Response(accountUser.error, { status: 404 });

	const user = accountUser.data;

	if (settings.adapter) {
		const handledUser = await settings.adapter.handleAccount(accountUser.data, config);
		if (!handledUser.ok) return new Response(handledUser.error, { status: 404 });
		user.id = handledUser.data.id;
	} else {
		const cuid = createId();
		user.id = cuid;
	}

	const encodedSessionToken = await createSession(user, settings);

	if (!encodedSessionToken.ok) return new Response(encodedSessionToken.error, { status: 404 });

	const redirect = event.cookies.get('SVAUTH_SIGNIN_REDIRECT') || `${base}/`;
	const response = new Response('Signed in.', {
		status: 301
	});
	response.headers.append('Set-Cookie', `SVAUTH_SESSION=${encodedSessionToken.data}; Path=/;`);
	response.headers.append('Set-Cookie', 'SVAUTH_SIGNIN_REDIRECT=; Path=/; Max-Age=0');
	response.headers.append('Location', redirect);
	return response;
};

export default handleGET;
