<script>
	import { signIn, signOut } from 'svauth/client';

	export let data;

	$: ({ session } = data);
</script>

<h1>Welcome to Svauth's Development SvelteKit Playground</h1>
<p>Visit <a href="https://kit.svelte.dev">kit.svelte.dev</a> to read the SvelteKit documentation</p>

{#if session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {session.user.email}</p>
	<img src={session.user.picture} alt="User profile" />
	<p>Expires on {session.expires.toUTCString()}</p>
{:else}
	<button on:click={() => signIn('google')}> Google sign in </button>
	<button on:click={() => signIn('discord')}> Discord sign in </button>
	<p>Not signed in</p>
{/if}
