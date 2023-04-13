<script lang="ts">
	import { session } from 'svauth/client';
</script>

{#if $session === false}
	<h1>LOADING</h1>
{:else if $session}
	<h1>{$session.user.email}</h1>
{/if}
