type ProviderId = 'google';
import { env } from '$env/dynamic/public';

export const signIn = async (providerId: ProviderId) => {
	const res = await fetch(env.PUBLIC_SVAUTH_PREFIX || '/auth', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ action: 'signIn', body: { providerId } })
	});

	if (!res.ok) throw new Error(res.statusText);

	const url = new URL(await res.text());

	(window as Window).location = url.toString();
};
