import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const GET = ((request) => {
	const session = request.locals.getSession();
	return json(session);
}) satisfies RequestHandler;
