# svauth

## Overview

Authentication for SvelteKit
Developed by Stephen Shkeda <stephenshkeda@gmail.com>

## Example

### Add Svauth Handler

```typescript
// hooks.server.ts
import Svauth from "svauth";
import { Google } from "svauth/providers";
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from "$env/static/private";

export const handle = Svauth({
  providers: [
    Google({
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
    }),
  ],
});
```

### Add Svauth Session to page

```typescript
// routes/+page.server.ts
import type { PageServerLoad } from "./$types";

export const load = ((event) => {
  return {
    session: event.locals.getSession(),
  };
}) satisfies PageServerLoad;
```

### Add Svelte Hook

```svelte
<script>
    // pages/+page.svelte

	import { signIn, signOut } from 'svauth/client';

	export let data;

	$: ({ session } = data);
</script>

{#if session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {session.user.email}</p>
	<p>Expires on {session.expires.toUTCString()}</p>
{:else}
	<button on:click={() => signIn('google')}> Sign in </button>
	<p>Not signed in</p>
{/if}
```
