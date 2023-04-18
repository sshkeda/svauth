import { env } from '$env/dynamic/public';
import { BROWSER } from 'esm-env';
import type { Session } from '$lib';
import { writable } from 'svelte/store';
import { page } from '$app/stores';

type ProviderId = 'google' | 'discord' | 'github';

const prefix = env.PUBLIC_SVAUTH_PREFIX || '/auth';

export const signIn = async (
	providerId: ProviderId,
	redirectUrl: string = window.location.pathname
) => {
	document.cookie = `SVAUTH_SIGNIN_REDIRECT=${redirectUrl}; Path=/; Max-Age=360`;

	(window as Window).location = `${prefix}/signin/${providerId}`;
};

export const signOut = async (redirectUrl: string = window.location.pathname) => {
	const res = await fetch(prefix, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ action: 'signOut' })
	});

	if (!res.ok) throw new Error(res.statusText);

	session.set(undefined);

	(window as Window).location = redirectUrl;
};

export const fetchSession = async (): Promise<Session | null | undefined> => {
	if (BROWSER) {
		const res = await fetch(`${prefix}/session`);

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
	page.subscribe((page) => {
		if ('session' in page.data) {
			set(page.data.session);
		} else {
			fetchSession().then((session) => set(session));
		}
	});
});
