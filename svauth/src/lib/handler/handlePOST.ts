import type { Settings } from '$lib';
import type { RequestEvent } from '@sveltejs/kit';
import { z } from 'zod';

const postBodySchema = z
	.object({
		action: z.literal('signIn'),
		body: z.object({
			providerId: z.string()
		})
	})
	.or(
		z.object({
			action: z.literal('signOut'),
			body: z.object({}).default({})
		})
	);

const handlePOST = async (event: RequestEvent, settings: Settings) => {
	const postBody = (await event.request.json()) as unknown;
	const parsedBody = postBodySchema.safeParse(postBody);

	if (!parsedBody.success) return new Response('Invalid Request.', { status: 400 });

	const { action } = parsedBody.data;

	if (action === 'signOut') {
		if (settings.adapter) {
			const sessionCookie = event.cookies.get('SVAUTH_SESSION');
			if (!sessionCookie) {
				return new Response('No session cookie.', { status: 400 });
			}

			const deleted = await settings.adapter.deleteSession(sessionCookie, settings);

			if (!deleted) {
				return new Response('Could not delete session.', { status: 400 });
			}
		}
		return new Response('Signed out.', {
			headers: {
				'Set-Cookie': 'SVAUTH_SESSION=; Path=/; Max-Age=0'
			}
		});
	} else {
		return new Response('Invalid action.', { status: 400 });
	}
};

export default handlePOST;
