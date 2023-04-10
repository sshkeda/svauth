<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { env } from '$env/dynamic/public';

	onMount(() => {
		// @ts-ignore
		const handleCredentialResponse = (response) => {
			const token = response.credential;
			goto('/auth/callback/token/?provider=google&token=' + token);
		};

		// @ts-ignore
		google.accounts.id.initialize({
			// @ts-ignore
			client_id: env.PUBLIC_GOOGLE_CLIENT_ID,
			callback: handleCredentialResponse
		});
		const googleButtonDiv = document.getElementById('googleButtonDiv');
		if (!googleButtonDiv) {
			throw new Error('googleButtonDiv not found');
		}
		// @ts-ignore
		google.accounts.id.renderButton(googleButtonDiv, {
			theme: 'outline',
			size: 'large'
		});
		// google.accounts.id.prompt(); // also display the One Tap dialog
	});
</script>

<svelte:head>
	<script src="https://accounts.google.com/gsi/client" async defer></script>
</svelte:head>

<div id="googleButtonContainer">
	<div id="googleButtonDiv" />
</div>

<style>
	#googleButtonContainer {
		display: inline-block;
	}
</style>
