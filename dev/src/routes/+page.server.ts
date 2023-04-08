import type { PageServerLoad } from './$types';

export const load = ((event) => {
	return {
		session: event.locals.getSession()
	};
}) satisfies PageServerLoad;
