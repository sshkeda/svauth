import type { OAuthProvider } from '$lib';

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
		nonce: true
	};
};

export default Google;
