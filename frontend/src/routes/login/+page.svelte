<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import * as Avatar from '$lib/components/ui/avatar';
	import * as Card from '$lib/components/ui/card';
	import FormattedMessage from '$lib/components/formatted-message.svelte';
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import WebAuthnService from '$lib/services/webauthn-service';
	import appConfigStore from '$lib/stores/application-configuration-store';
	import userStore from '$lib/stores/user-store';
	import type { OidcClientMetaData } from '$lib/types/oidc.type';
	import { cachedProfilePicture } from '$lib/utils/cached-image-util';
	import { getWebauthnErrorMessage } from '$lib/utils/error-util';
	import { shouldUseBrowserNavigationForRedirect } from '$lib/utils/redirection-util';
	import { startAuthentication } from '@simplewebauthn/browser';
	import { fade } from 'svelte/transition';
	import ClientProviderImages from '../authorize/components/client-provider-images.svelte';
	import LoginLogoErrorSuccessIndicator from './components/login-logo-error-success-indicator.svelte';

	let {
		data
	}: {
		data: {
			redirect: string;
			client: OidcClientMetaData | null;
		};
	} = $props();

	const webauthnService = new WebAuthnService();

	let isLoading = $state(false);
	let success = $state(false);
	let error: string | undefined = $state(undefined);
	const requiresForwardAuthConsent = $derived(!!data.client && !data.client.skipConsent);
	const showForwardAuthConsent = $derived(requiresForwardAuthConsent && !!$userStore && !error);
	const fullName = $derived.by(() => {
		if (!$userStore) {
			return '';
		}

		if ($userStore.displayName) {
			return $userStore.displayName;
		}

		return [$userStore.firstName, $userStore.lastName].filter(Boolean).join(' ').trim();
	});
	const primaryName = $derived(fullName || $userStore?.email || '');

	async function redirectToTarget() {
		success = true;
		await new Promise((resolve) => setTimeout(resolve, data.client ? 1400 : 500));
		if (shouldUseBrowserNavigationForRedirect(data.redirect || '/settings')) {
			window.location.assign(data.redirect || '/settings');
		} else {
			goto(data.redirect || '/settings');
		}
	}

	async function authenticate() {
		error = undefined;
		success = false;
		isLoading = true;
		try {
			const loginOptions = await webauthnService.getLoginOptions();
			const authResponse = await startAuthentication({ optionsJSON: loginOptions });
			const user = await webauthnService.finishLogin(authResponse);

			await userStore.setUser(user);
			await invalidateAll();
			if (!requiresForwardAuthConsent) {
				await redirectToTarget();
			}
		} catch (e) {
			success = false;
			error = getWebauthnErrorMessage(e);
		}
		isLoading = false;
	}

	async function useDifferentAccount() {
		success = false;
		error = undefined;
		await webauthnService.logout();
		await invalidateAll();
	}

	async function handlePrimaryAction() {
		if (showForwardAuthConsent) {
			isLoading = true;
			error = undefined;
			try {
				await redirectToTarget();
			} finally {
				isLoading = false;
			}
			return
		}

		await authenticate();
	}
</script>

<svelte:head>
	<title>{data.client ? m.sign_in_to({ name: data.client.name }) : m.sign_in()}</title>
</svelte:head>

<SignInWrapper showAlternativeSignInMethodButton>
	<div class="flex justify-center">
		{#if data.client}
			<ClientProviderImages client={data.client} {success} error={!!error} />
		{:else}
			<LoginLogoErrorSuccessIndicator {success} error={!!error} />
		{/if}
	</div>
	<h1 class="font-gloock mt-5 text-3xl font-bold sm:text-4xl">
		{#if data.client}
			{m.sign_in_to({ name: data.client.name })}
		{:else}
			{m.sign_in_to_appname({ appName: $appConfigStore.appName })}
		{/if}
	</h1>
	{#if error}
		<p class="text-muted-foreground mt-2" in:fade>
			{error}. {m.please_try_to_sign_in_again()}
		</p>
	{:else if showForwardAuthConsent}
		<p class="text-muted-foreground mt-2" in:fade>
			<FormattedMessage
				m={m.do_you_want_to_sign_in_to_client_with_your_app_name_account({
					client: data.client!.name,
					appName: $appConfigStore.appName
				})}
			/>
		</p>
	{:else if data.client}
		<p class="text-muted-foreground mt-2" in:fade>
			<FormattedMessage
				m={m.do_you_want_to_sign_in_to_client_with_your_app_name_account({
					client: data.client.name,
					appName: $appConfigStore.appName
				})}
			/>
		</p>
	{:else}
		<p class="text-muted-foreground mt-2" in:fade>
			{m.authenticate_with_passkey_to_access_account()}
		</p>
	{/if}
	{#if showForwardAuthConsent}
		<div class="mt-10 flex w-full max-w-md flex-col items-center">
			<Card.Root class="mb-3 py-4 w-full">
				<Card.Content class="flex items-center gap-4">
					<Avatar.Root class="size-11 shrink-0">
						<Avatar.Image src={cachedProfilePicture.getUrl($userStore!.id)} />
					</Avatar.Root>
					<div class="flex min-w-0 flex-col text-start">
						<p class="truncate text-base leading-tight font-medium">
							{primaryName}
						</p>
						{#if fullName && $userStore?.email}
							<p class="text-muted-foreground mt-1 truncate text-sm leading-tight">
								{$userStore.email}
							</p>
						{/if}
					</div>
				</Card.Content>
			</Card.Root>
			<div class="mb-8 flex justify-center">
				<button
					type="button"
					class="text-muted-foreground text-xs transition-colors hover:underline"
					onclick={useDifferentAccount}
				>
					{m.use_a_different_account()}
				</button>
			</div>
		</div>
	{/if}
	<div class="mt-10 flex justify-center gap-3 w-full max-w-[450px]">
		{#if showForwardAuthConsent}
			<Button class="w-[50%]" variant="secondary" href={document.referrer || '/'}>
				{m.cancel()}
			</Button>
		{:else if $appConfigStore.allowUserSignups === 'open' && !data.client}
			<Button class="w-[50%]" variant="secondary" href="/signup">
				{m.signup()}
			</Button>
		{/if}
		<Button
			class={showForwardAuthConsent
				? 'w-[50%]'
				: $appConfigStore.allowUserSignups === 'open' && !data.client
				? 'w-[50%]'
				: 'w-[80%] sm:w-[40%]'}
			{isLoading}
			onclick={handlePrimaryAction}
			autofocus={true}
		>
			{error ? m.try_again() : data.client ? m.sign_in() : m.authenticate()}
		</Button>
	</div>
</SignInWrapper>
