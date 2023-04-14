<script lang="ts">
	import { session, signIn, signOut } from 'svauth/client';
	import { GoogleSignInButton } from 'svauth/components';
</script>

<h1>Client Load Testing</h1>
<p><a href="/">back</a></p>

{#if $session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {$session.user.email}</p>
	<p>ID: {$session.user.id}</p>
	<img src={$session.user.picture} alt="User profile" />
	<p>Token expires on {$session.expires.toUTCString()}</p>
{:else}
	<GoogleSignInButton />
	<button on:click={() => signIn('google')}> Google sign in </button>
	<button on:click={() => signIn('discord')}> Discord sign in </button>
	<p>Not signed in</p>
{/if}
