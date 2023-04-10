<script lang="ts">
	import { signIn, signOut, getSession, type Session } from 'svauth/client';
	import { GoogleSignInButton } from 'svauth/components';

	let session: null | undefined | Session = null;
	let sessionLoaded = false;

	getSession().then((s) => {
		session = s;
		sessionLoaded = true;
	});
</script>

<h1>Welcome to svauth's Development SvelteKit Playground</h1>
<p>
	Visit <a href="https://github.com/sshkeda/svauth">svauth's github repository</a> to read the svauth
	documentation
</p>

{#if session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {session.user.email}</p>
	<p>ID: {session.user.id}</p>
	<img src={session.user.picture} alt="User profile" />
	<p>Token expires on {session.expires.toUTCString()}</p>
{:else}
	<GoogleSignInButton />
	<button on:click={() => signIn('google')}> Google sign in </button>
	<button on:click={() => signIn('discord')}> Discord sign in </button>
	<p>Not signed in</p>
{/if}

<style>
	:global(body) {
		font-family: 'Segoe UI';
	}
</style>
