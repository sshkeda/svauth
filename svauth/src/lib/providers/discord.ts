import type { OAuthProvider } from '$lib';

interface DiscordConfig {
	clientId: string;
	clientSecret: string;
}

const Discord = ({ clientId, clientSecret }: DiscordConfig): OAuthProvider => {
	return {
		name: 'discord',
		clientId,
		clientSecret,
		scope: 'email identify',
		authorizationEndpoint: 'https://discord.com/api/oauth2/authorize',
		tokenEndpoint: 'https://discord.com/api/oauth2/token'
	};
};

export default Discord;
