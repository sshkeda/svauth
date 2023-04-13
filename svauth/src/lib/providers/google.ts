import type { OAuthProvider, SafeResult, User } from '$lib';
import { z } from 'zod';
import * as jose from 'jose';

interface GoogleConfig {
	clientId: string;
	clientSecret: string;
}

const googleSchema = z.object({
	sub: z.string(),
	name: z.string(),
	email: z.string(),
	picture: z.string()
});

const tokenSchema = z.object({
	id_token: z.string()
});

/**
 * Svauth Google Provider
 *
 * @see https://developers.google.com/identity/protocols/oauth2/openid-connect
 *
 */
const Google = ({ clientId, clientSecret }: GoogleConfig): OAuthProvider => {
	const name = 'google';
	const scope = 'openid email profile';
	const authorizationEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
	const tokenEndpoint = 'https://oauth2.googleapis.com/token';
	const nonce = true;
	const jwksEndpoint = 'https://www.googleapis.com/oauth2/v3/certs';

	async function verifyToken(idToken: string): Promise<SafeResult<jose.JWTPayload>> {
		try {
			const JWKS = jose.createRemoteJWKSet(new URL(jwksEndpoint));

			const decodedToken = await jose.jwtVerify(idToken, JWKS);

			return {
				ok: true,
				data: decodedToken.payload
			};
		} catch (err) {
			return {
				ok: false,
				error: 'Failed to verify JWT token.'
			};
		}
	}

	async function parseUser(idTokenPayload: jose.JWTPayload): Promise<SafeResult<User>> {
		try {
			const googleUser = googleSchema.parse(idTokenPayload);

			const user = {
				id: googleUser.sub,
				name: googleUser.name,
				email: googleUser.email,
				picture: googleUser.picture
			};

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
	}
	async function getUser(exchangeResponse: unknown): Promise<SafeResult<User>> {
		const token = tokenSchema.safeParse(exchangeResponse);

		if (!token.success)
			return {
				ok: false,
				error: 'Invalid token response.'
			};

		const { id_token } = token.data;

		const idTokenPayload = await verifyToken(id_token);

		if (!idTokenPayload.ok)
			return {
				ok: false,
				error: idTokenPayload.error
			};

		const user = await parseUser(idTokenPayload.data);

		return user;
	}

	return {
		name,
		clientId,
		clientSecret,
		scope,
		authorizationEndpoint,
		tokenEndpoint,
		nonce,
		jwksEndpoint,
		verifyToken,
		parseUser,
		getUser
	};
};

export default Google;
