<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { env } from '$env/dynamic/public';

	const prefix = env.PUBLIC_SVAUTH_PREFIX || '/auth';

	let googleScript: HTMLScriptElement;

	export let oneTap = false;

	// https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/google-one-tap/index.d.ts
	// https://developers.google.com/identity/gsi/web/reference/js-reference#GsiButtonConfiguration

	export let type: 'standard' | 'icon' = 'standard';
	export let theme: 'outline' | 'filled_blue' | 'filled_black' = 'outline';
	export let size: 'large' | 'medium' | 'small' = 'large';
	export let text: 'signin_with' | 'signup_with' | 'continue_with' | 'signin' = 'signin_with';
	export let shape: 'rectangular' | 'pill' | 'circle' | 'square' = 'rectangular';
	export let logo_alignment: 'left' | 'center' = 'left';
	export let width: number | undefined = undefined;
	export let locale: string | undefined = undefined;

	onMount(async () => {
		interface CredentialResponse {
			credential: string;
		}

		const handleCredentialResponse = (response: CredentialResponse) => {
			const token = response.credential;
			goto('/auth/callback/token/?provider=google&token=' + token);
		};

		const initializeGoogle = async () => {
			const client_id = await fetch(`${prefix}/client_id/google`).then((res) => res.text());

			// @ts-ignore
			google.accounts.id.initialize({
				client_id,
				callback: handleCredentialResponse
			});
			const googleButtonDiv = document.getElementById('googleButtonDiv');
			if (!googleButtonDiv) {
				throw new Error('googleButtonDiv not found');
			}
			// @ts-ignore
			google.accounts.id.renderButton(googleButtonDiv, {
				type,
				theme,
				size,
				text,
				shape,
				width,
				logo_alignment,
				locale
			});

			if (oneTap) {
				// @ts-ignore
				google.accounts.id.prompt();
			}
		};

		try {
			initializeGoogle();
		} catch (err) {
			googleScript.addEventListener('load', initializeGoogle);
		}

		return () => {
			googleScript.removeEventListener('load', initializeGoogle);
		};
	});
</script>

<svelte:head>
	<script
		src="https://accounts.google.com/gsi/client"
		defer
		async
		bind:this={googleScript}
	></script>
</svelte:head>

<div id="googleButtonContainer">
	<div id="googleButtonDiv" />
</div>

<style>
	#googleButtonContainer {
		display: inline-block;
	}
</style>
