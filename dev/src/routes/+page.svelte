<script>
	import { signIn } from 'svauth/client';
</script>

<h1>Welcome to Svauth's Development SvelteKit Playground</h1>
<p>Visit <a href="https://kit.svelte.dev">kit.svelte.dev</a> to read the SvelteKit documentation</p>

<button on:click={() => signIn('google')}> Sign in </button>
