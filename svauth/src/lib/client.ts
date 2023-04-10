type ProviderId = 'google' | 'discord';
import { env } from '$env/dynamic/public';
import { goto } from '$app/navigation';
import { BROWSER } from 'esm-env';
import type { Session } from '$lib';

export type { Session } from '$lib';

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

export const signOut = async () => {
	const res = await fetch(env.PUBLIC_SVAUTH_PREFIX || '/auth', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ action: 'signOut' })
	});

	if (!res.ok) throw new Error(res.statusText);

	const url = await res.text();

	goto(url, {
		invalidateAll: true
	});
};

export const getSession = async () => {
	if (BROWSER) {
		const res = await fetch(
			env.PUBLIC_SVAUTH_PREFIX ? `${env.PUBLIC_SVAUTH_PREFIX}/session` : '/auth/session'
		);

		if (!res.ok) throw new Error(res.statusText);

		const session = await res.json();
		if (session) {
			session.expires = new Date(session.expires);
			session.issuedAt = new Date(session.issuedAt);
			return session as Session;
		} else {
			return session;
		}
	} else {
		return null;
	}
};
