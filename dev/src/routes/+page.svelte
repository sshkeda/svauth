<script lang="ts">
	import { signIn, signOut } from 'svauth/client';

	import type { PageData } from './$types';

	export let data: PageData;

	const { session } = data;
</script>

<h1>Welcome to Svauth's Development SvelteKit Playground</h1>
<p>Visit <a href="https://kit.svelte.dev">kit.svelte.dev</a> to read the SvelteKit documentation</p>

<button on:click={() => signIn('google')}> Sign in </button>
<button on:click={() => signOut()}> Sign out </button>

{#if session}
	<p>Logged in as {session.email}</p>
{/if}
