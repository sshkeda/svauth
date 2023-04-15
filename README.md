# svauth

## Overview

Authentication for SvelteKit
Developed by Stephen Shkeda <stephenshkeda@gmail.com>

## Get Started

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

### 2. (Optional) Get Session During Load

```typescript
// routes/+page.server.ts
import type { PageServerLoad } from "./$types";

export const load = (async (event) => {
  return {
    session: await event.locals.getSession(),
  };
}) satisfies PageServerLoad;
```

### 3. Import Session

```svelte
<script lang="ts">
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
