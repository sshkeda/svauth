<script lang="ts">
	import { session, signOut } from 'svauth/client';
	import { GoogleSignInButton } from 'svauth/components';
</script>

{#if $session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {$session.user.email}</p>
	<p>ID: {$session.user.id}</p>
	<img src={$session.user.picture} alt="User profile" />
	<p>Token expires on {$session.expires.toUTCString()}</p>
{:else}
	<GoogleSignInButton />
	<p>Not signed in</p>
{/if}
