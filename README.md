<p align="center">
	<img src="https://user-images.githubusercontent.com/129692066/232321448-b9bae8f2-7bbf-4314-aff9-845bb8e31277.png" alt="svauth Logo" />
	<h3 align="center">svauth</h3>
	<p align="center">Authentication for SvelteKit</p>
	<p align="center">Developed by Stephen Shkeda <stephenshkeda@gmail.com></p>
		
</p>

## Overview

**svauth** is a complete open source authentication solution for [SvelteKit](https://kit.svelte.dev/) applications.

Designed from the ground up to support SvelteKit and serverless.

Heavily inspired by [NextAuth.js](https://github.com/nextauthjs/next-auth).

Written for [Svelte Hack 2023](https://hack.sveltesociety.dev/).

This is a monorepo containing the following packages / projects:

1. The primary `svauth` package
2. A development test application

## Get Started

### Install svauth

```
npm install svauth
yarn add svauth
pnpm add svauth
```

### Add Svauth Handler

```typescript
// hooks.server.ts
import Svauth from 'svauth';
import { Google } from 'svauth/providers';
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private';

export const handle = Svauth({
	providers: [
		Google({
			clientId: GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET
		})
	]
});
```

### (Optional) Get Session During Load

```typescript
// routes/+page.server.ts
import type { PageServerLoad } from './$types';

export const load = (async (event) => {
	return {
		session: await event.locals.getSession()
	};
}) satisfies PageServerLoad;
```

### Import Session

```svelte
<script lang="ts">
	// routes/+page.svelte
	import { session, signIn, signOut } from 'svauth/client';
</script>

{#if $session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {$session.user.email}</p>
{:else}
	<button on:click={() => signIn('google')}> Google sign in </button>
	<p>Not signed in</p>
{/if}
```
