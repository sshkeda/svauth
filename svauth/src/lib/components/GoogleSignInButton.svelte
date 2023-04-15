<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { env } from '$env/dynamic/public';

	const prefix = env.PUBLIC_SVAUTH_PREFIX || '/auth';

	let googleScript: HTMLScriptElement;

	export let oneTap: boolean = false;

	// https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/google-one-tap/index.d.ts
	interface GsiButtonConfiguration {
		type?: 'standard' | 'icon';
		theme?: 'outline' | 'filled_blue' | 'filled_black';
		size?: 'large' | 'medium' | 'small';
		text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
		shape?: 'rectangular' | 'pill' | 'circle' | 'square';
		logo_alignment?: 'left' | 'center';
		width?: number;
		locale?: string;
	}

	export let config: GsiButtonConfiguration = {
		theme: 'outline',
		size: 'large'
	};

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
			console.log(client_id);

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
			google.accounts.id.renderButton(googleButtonDiv, config);

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
