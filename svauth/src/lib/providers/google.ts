import type { OAuthProvider } from '$lib';
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

/**
 * Svauth Google Provider
 *
 * @see https://developers.google.com/identity/protocols/oauth2/openid-connect
 *
 */
const Google = ({ clientId, clientSecret }: GoogleConfig): OAuthProvider => {
	return {
		name: 'google',
		clientId,
		clientSecret,
		scope: 'openid email profile',
		authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
		tokenEndpoint: 'https://oauth2.googleapis.com/token',
		nonce: true,
		jwksEndpoint: 'https://www.googleapis.com/oauth2/v3/certs',
		verifyToken: async function (token: string) {
			try {
				const JWKS = jose.createRemoteJWKSet(new URL(this.jwksEndpoint as string));

				const decodedToken = await jose.jwtVerify(token, JWKS);

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
		},
		parseToken: async function (tokenJson: unknown) {
			const tokenSchema = z.object({
				id_token: z.string()
			});

			const parsedToken = tokenSchema.safeParse(tokenJson);

			if (!parsedToken.success)
				return {
					ok: false,
					error: 'Invalid token response.'
				};

			const { id_token } = parsedToken.data;

			return this.verifyToken(id_token);
		},
		parseUser: async function (jwt: jose.JWTPayload) {
			try {
				const googleUser = googleSchema.parse(jwt);

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
	};
};

export default Google;
