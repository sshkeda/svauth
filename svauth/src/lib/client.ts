type ProviderId = 'google' | 'discord';
import { env } from '$env/dynamic/public';
import { goto } from '$app/navigation';
import { BROWSER } from 'esm-env';
import type { Session } from '$lib';
import { writable } from 'svelte/store';

export type { Session } from '$lib';

export const signIn = async (
	providerId: ProviderId,
	redirectUrl: string = window.location.pathname
) => {
	const res = await fetch(env.PUBLIC_SVAUTH_PREFIX || '/auth', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ action: 'signIn', body: { providerId } })
	});

	if (!res.ok) throw new Error(res.statusText);

	const url = new URL(await res.text());

	// Because redirectUrl is lost when the user is redirected to the OAuth provider,
	// I set it as a temporary cookie so that Svauth server can read it when the user is redirected back from OAuth.

	document.cookie = `SVAUTH_SIGNIN_REDIRECT=${redirectUrl}; path=/; max-age=360`;

	(window as Window).location = url.toString();
};

export const signOut = async (redirectUrl: string = window.location.pathname) => {
	const res = await fetch(env.PUBLIC_SVAUTH_PREFIX || '/auth', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ action: 'signOut' })
	});

	if (!res.ok) throw new Error(res.statusText);

	session.set(undefined);
	await goto(redirectUrl, {
		invalidateAll: true
	});
};

export const fetchSession = async (): Promise<Session | null | undefined> => {
	if (BROWSER) {
		const res = await fetch(
			env.PUBLIC_SVAUTH_PREFIX ? `${env.PUBLIC_SVAUTH_PREFIX}/session` : '/auth/session'
		);

		if (!res.ok) throw new Error(res.statusText);

		const data = await res.json();

		const { session } = data;

		if (session) {
			session.expires = new Date(session.expires);
			session.issuedAt = new Date(session.issuedAt);
			return session as Session;
		} else {
			return session;
		}
	} else {
		return undefined;
	}
};

/**
 * A Svelte writable store that holds the current user session information.
 *
 * The store has 4 possible values:
 * - Session: The user's current session.
 * - null: The credentials are wrong or the session has expired.
 * - undefined: There is no session.
 * - false: The session is loading.
 */
export const session = writable<Session | null | undefined | false>(false, (set) => {
	fetchSession().then((session) => set(session));
});
