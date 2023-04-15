import type { PageServerLoad } from './$types';

export const load = (async (event) => {
	console.log("LOAD")
	return {
		session: await event.locals.getSession()
	};
}) satisfies PageServerLoad;
