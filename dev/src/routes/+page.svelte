<script>
	import { signIn, signOut, session } from 'svauth/client';
	import { SignInWithGoogleButton } from 'svauth/components';
</script>

<h1>Welcome to svauth's Development SvelteKit Playground</h1>
<p>
	Visit <a href="https://github.com/sshkeda/svauth">svauth's github repository</a> to read the svauth
	documentation
</p>
<p>
	Test out session with no load component <a href="/no-load">here.</a>
</p>

{#if $session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {$session.user.email}</p>
	<p>ID: {$session.user.id}</p>
	<img src={$session.user.picture} alt="User profile" referrerpolicy="no-referrer" />
	<p>Token expires on {$session.expires.toUTCString()}</p>
{:else}
	<SignInWithGoogleButton />
	<button on:click={() => signIn('google')}> Google sign in </button>
	<button on:click={() => signIn('discord')}> Discord sign in </button>
	<button on:click={() => signIn('github')}>GitHub sign in</button>
	<p>Not signed in</p>
{/if}

<style>
	:global(body) {
		font-family: 'Segoe UI';
	}
</style>
