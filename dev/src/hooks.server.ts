import Svauth from 'svauth';
import { Google, Discord, GitHub } from 'svauth/providers';
import {
	GOOGLE_CLIENT_SECRET,
	DISCORD_CLIENT_ID,
	DISCORD_CLIENT_SECRET,
	GITHUB_CLIENT_ID,
	GITHUB_CLIENT_SECRET
} from '$env/static/private';

import { PUBLIC_GOOGLE_CLIENT_ID } from '$env/static/public';

export const handle = Svauth({
	providers: [
		Google({
			clientId: PUBLIC_GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET
		}),
		Discord({
			clientId: DISCORD_CLIENT_ID,
			clientSecret: DISCORD_CLIENT_SECRET
		}),
		GitHub({
			clientId: GITHUB_CLIENT_ID,
			clientSecret: GITHUB_CLIENT_SECRET
		})
	],
	expires: '30d'
});
