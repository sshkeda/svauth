<p align="center">
	<img
	src="https://user-images.githubusercontent.com/129692066/232329591-2236ead0-21c8-43aa-a9de-c0a2659c6a9d.png"
	alt="svauth logo"
	align="center" />
	<h1 align="center">svauth</h1>
	<p align="center">
		Authentication for SvelteKit
		<br />
		Developed by Stephen Shkeda
		<br />
		stephenshkeda@gmail.com
	</p>	
</p>

## Table of Contents

- [Overview](#overview)
- [Get Started](#get-started)
- [Features](#features)
- [Security](#security)
- [Environment Variables](#environment-variables)
- [Server API](#server-api)
  - [Svauth](#svauth)
  - [event.locals](#eventlocals)
- [Client API](#client-api)
  - [session](#session)
  - [Session (Object)](#session-object)
  - [User (Object)](#user-object)
  - [signIn](#signin)
  - [signOut](#signout)
- [Providers](#providers)
  - [Google](#google)
  - [Discord](#discord)
  - [GitHub](#github)
- [Components](#components)
  - [SignInWithGoogleButton](#signinwithgooglebutton)
- [License](#license)

## Overview

**svauth** is a complete open source authentication solution for [SvelteKit](https://kit.svelte.dev/) applications.

Designed from the ground up to support SvelteKit and serverless.

Heavily inspired by [NextAuth.js](https://github.com/nextauthjs/next-auth).

Written for [Svelte Hack 2023](https://hack.sveltesociety.dev/).

This is a monorepo containing the following packages / projects:

1. The primary `svauth` package
2. A development test application

## Get Started

### Install svauth

```
npm install svauth
yarn add svauth
pnpm add svauth
```

### Add Svauth Handler

```typescript
// hooks.server.ts
import Svauth from 'svauth';
import { Google } from 'svauth/providers';
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private';

export const handle = Svauth({
	providers: [
		Google({
			clientId: GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET
		})
	]
});
```

### (Optional) Get Session During Load

```typescript
// routes/+page.server.ts
import type { PageServerLoad } from './$types';

export const load = (async (event) => {
	return {
		session: await event.locals.getSession()
	};
}) satisfies PageServerLoad;
```

### Import Session

```svelte
<script lang="ts">
	// routes/+page.svelte
	import { session, signIn, signOut } from 'svauth/client';
</script>

{#if $session}
	<button on:click={() => signOut()}> Sign out </button>
	<p>Logged in as {$session.user.email}</p>
{:else}
	<button on:click={() => signIn('google')}> Sign in with Google </button>
	<p>Not signed in</p>
{/if}
```

## Features

- **OAuth Providers** - Seamless integration with Google, Discord, and GitHub.
- **Serverless** - Designed to work with serverless environments.
- **Session Management** - Built-in session management for server and client-side rendering.
- **TypeScript** - Written in TypeScript and includes type definitions.
- **Security** - Designed to be secure by default and encourage best practices for safeguarding user data.
- **Customizable Components** - Pre-built, customizable components like the SignInWithGoogleButton for a smoother user authentication experience.

## Security

- **CSRF Protection** - SvelteKit's built-in CSRF protection is used to prevent CSRF attacks.
- **JWT Encryption** - When JSON Web Tokens are enabled, they are encrypted by default (JWE) with A256GCM.
- **Client Independence** - Doesn't rely on client-side JavaScript.
- **Secure Cookie Management** - Signed, prefixed, server-only cookies.
- **OWASP Compliance** - Attempts to implement the latest guidance published by [Open Web Application Security Project](https://owasp.org/).

Please contact me directly, stephenshkeda@gmail.com, to report serious issues that might impact the security of sites using svauth.

## Environment Variables

| Name                 | Description                             |
| -------------------- | --------------------------------------- |
| SVAUTH_SECRET        | The secret used to encrypt the session. |
| SVAUTH_URL           | The URL of the application.             |
| PUBLIC_SVAUTH_PREFIX | The prefix used for the svauth routes.  |

For production environments, if SVAUTH_URL is not set, VERCEL_URL will be used. For development environments, SVAUTH_URL defaults to localhost:5173.

PUBLIC_SVAUTH_PREFIX is optional and defaults to /auth.

## Server API

### Svauth

The `Svauth` function is used to create the Svauth handler.

#### Parameters

| Name      | Type            | Description         |
| --------- | --------------- | ------------------- |
| `options` | `SvauthOptions` | The options object. |

#### SvauthOptions

| Name        | Type                 | Default | Description                                                                                                                                                                           |
| ----------- | -------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `providers` | `Provider[]`         |         | An array of providers.                                                                                                                                                                |
| `expires`   | `number` \| `string` | `30d`   | The expiration time of the session. When number is passed that is used as a value in seconds, when string is passed it is resolved to a time span and added to the current timestamp. |

#### Example

```typescript
// hooks.server.ts
import Svauth from 'svauth';

export const handle = Svauth({
	providers: [
		Google({
			clientId: GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET
		})
	],
	expires: '14d'
});
```

### event.locals

The `event.locals` object contains the following properties:

| Name           | Type    | Description                  |
| -------------- | ------- | ---------------------------- |
| `getSession()` | `async` | Returns the current session. |

#### Example

```typescript
// routes/+page.server.ts
import type { PageServerLoad } from './$types';

export const load = (async (event) => {
	return {
		session: await event.locals.getSession()
	};
}) satisfies PageServerLoad;
```

## Client API

### session

The `session` store is the easiest way to obtain information on current session.

`session` returns 4 possible values:

- **Session** - The user's current session.
- **null** - The credentials are wrong or the session has expired.
- **undefined** - There is no session.
- **false** - The session is loading.

Note: If you are obtaining the session during load, `session` will not return `false`.

#### Example

```svelte
<script lang="ts">
	import { session } from 'svauth/client';
</script>

{#if $session}
	<p>Logged in as {$session.user.email}</p>
{:else}
	<p>Not signed in</p>
{/if}
```

### Session Object

The `Session` object is returned by the `session` store.

#### Properties

| Name       | Type   | Description                         |
| ---------- | ------ | ----------------------------------- |
| `User`     | `User` | The user object.                    |
| `expires`  | `Date` | The expiration time of the session. |
| `issuedAt` | `Date` | The time the session was issued.    |

### User Object

The `User` object is found inside the `Session` object.

#### Properties

| Name    | Type     | Description                |
| ------- | -------- | -------------------------- |
| `id`    | `string` | The user's ID.             |
| `email` | `string` | The user's email.          |
| `name`  | `string` | The user's name.           |
| `image` | `string` | A link to the user's image |

### signIn

The `signIn` function is used to sign in a user.

#### Parameters

| Name       | Type     | Default                 | Description                                        |
| ---------- | -------- | ----------------------- | -------------------------------------------------- |
| `provider` | `string` |                         | The provider to sign in with.                      |
| `redirect` | `string` | Current user's location | The URL to redirect the user to after signing out. |

#### Example

```svelte
<script lang="ts">
	import { signIn } from 'svauth/client';
</script>

<button on:click={() => signIn('google')}> Sign in with Google </button>
```

### signOut

The `signOut` function is used to sign out a user.

#### Parameters

| Name       | Type     | Default                 | Description                                        |
| ---------- | -------- | ----------------------- | -------------------------------------------------- |
| `redirect` | `string` | Current user's location | The URL to redirect the user to after signing out. |

#### Example

```svelte
<script lang="ts">
	import { signOut } from 'svauth/client';
</script>

<button on:click={() => signOut()}> Sign out </button>
```

## Providers

Currently, svauth has support for three OAuth providers:

- [Google](#google)
- [Discord](#discord)
- [GitHub](#github)

In the future, I plan to add support for more providers.

### Google

#### Documentation

https://developers.google.com/identity/protocols/oauth2
https://developers.google.com/identity/openid-connect/openid-connect

#### Configuration

https://console.developers.google.com/apis/credentials

The "Authorized redirect URIs" used when creating the credentials must include your full domain and end in the callback path.

For example:

- Production: https://{YOUR_DOMAIN}/auth/callback/google
- Development: http://localhost:5173/auth/callback/google

#### Example

```typescript
// hooks.server.ts
import Svauth from 'svauth';
import { Google } from 'svauth/providers';
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private';

export const handle = Svauth({
	providers: [
		Google({
			clientId: GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET
		})
	]
});
```

### Discord

#### Documentation

https://discord.com/developers/docs/topics/oauth2

#### Configuration

https://discord.com/developers/applications

The "Redirects" used when creating the credentials must include your full domain and end in the callback path.

For example:

- Production: https://{YOUR_DOMAIN}/auth/callback/discord
- Development: http://localhost:5173/auth/callback/discord

#### Example

```typescript
// hooks.server.ts
import Svauth from 'svauth';
import { Discord } from 'svauth/providers';
import { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET } from '$env/static/private';

export const handle = Svauth({
	providers: [
		Discord({
			clientId: DISCORD_CLIENT_ID,
			clientSecret: DISCORD_CLIENT_SECRET
		})
	]
});
```

### GitHub

#### Documentation

https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps

#### Configuration

https://github.com/settings/developers

The "Authorization callback URL" used when creating the credentials must include your full domain and end in the callback path.

For example:

- Production: https://{YOUR_DOMAIN}/auth/callback/github
- Development: http://localhost:5173/auth/callback/github

#### Example

```typescript
// hooks.server.ts
import Svauth from 'svauth';
import { GitHub } from 'svauth/providers';
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET } from '$env/static/private';

export const handle = Svauth({
	providers: [
		GitHub({
			clientId: GITHUB_CLIENT_ID,
			clientSecret: GITHUB_CLIENT_SECRET
		})
	]
});
```

## Components

### SignInWithGoogleButton

The `SignInWithGoogleButton` component is a simple button that will sign the user in with Google.

#### Documentation

https://developers.google.com/identity/gsi/web/guides/overview

#### Configuration

https://console.developers.google.com/apis/credentials

The "Authorized JavaScript origins" used when creating the credentials must include your HTTP origins.

For example:

- Production: https://{YOUR_DOMAIN}
- Development: http://localhost:5173 and http://localhost

#### Props

| Name             | Type                                                          | Default       | Description                            |
| ---------------- | ------------------------------------------------------------- | ------------- | -------------------------------------- |
| `oneTap`         | `boolean`                                                     | `false`       | Whether to use Google One Tap sign in. |
| `type`           | `standard` \| `icon`                                          | `standard`    | The button type.button.                |
| `theme`          | `outline` \| `filled_blue` \| `filled_black`                  | `outline`     | The button theme.                      |
| `size`           | `large` \| `medium` \| `small`                                | `large`       | The button size.                       |
| `text`           | `signin_with` \| `signup_with` \| `continue_with` \| `signin` | `signin_with` | The button text.                       |
| `shape`          | `rectangular` \| `pill` \| `circle` \| `square`               | `rectangular` | The button shape.                      |
| `logo_alignment` | `left` \| `center`                                            | `left`        | The Google logo alignment.             |
| `width`          | `number`                                                      |               | The button width, in pixels.           |
| `locale`         | `string`                                                      |               | The button language.                   |

#### Example

```svelte
<script lang="ts">
	// routes/+page.svelte
	import { SignInWithGoogleButton } from 'svauth/components';
</script>

<SignInWithGoogleButton />
```

## License

ISC

Portions of this page are reproduced from work created and [shared by Google]("https://developers.google.com/readme/policies") and used according to terms described in the [Creative Commons 4.0 Attribution License](https://creativecommons.org/licenses/by/4.0/).
