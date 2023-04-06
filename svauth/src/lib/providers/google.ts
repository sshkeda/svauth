import type { Provider } from '$lib';

interface GoogleConfig {
	clientId: string;
	clientSecret: string;
}

const Google = ({ clientId, clientSecret }: GoogleConfig): Provider => {
	return {
		client_id: clientId,
		client_secret: clientSecret
	};
};

export default Google;
