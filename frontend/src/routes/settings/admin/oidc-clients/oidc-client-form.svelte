<script lang="ts">
	import FormInput from '$lib/components/form/form-input.svelte';
	import SwitchWithLabel from '$lib/components/form/switch-with-label.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as Tabs from '$lib/components/ui/tabs';
	import { m } from '$lib/paraglide/messages';
	import type {
		HTTPHeader,
		OidcClient,
		OidcClientCreateWithLogo,
		OidcClientUpdateWithLogo
	} from '$lib/types/oidc.type';
	import { cachedOidcClientLogo } from '$lib/utils/cached-image-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { cn } from '$lib/utils/style';
	import { callbackUrlSchema, emptyToUndefined, optionalUrl } from '$lib/utils/zod-util';
	import { LucideChevronDown, LucideMoon, LucideSun } from '@lucide/svelte';
	import { slide } from 'svelte/transition';
	import { z } from 'zod/v4';
	import FederatedIdentitiesInput from './federated-identities-input.svelte';
	import OidcCallbackUrlInput from './oidc-callback-url-input.svelte';
	import OidcClientImageInput from './oidc-client-image-input.svelte';

	let {
		callback,
		existingClient,
		mode
	}: {
		existingClient?: OidcClient;
		callback: (client: OidcClientCreateWithLogo | OidcClientUpdateWithLogo) => Promise<boolean>;
		mode: 'create' | 'update';
	} = $props();
	let isLoading = $state(false);
	let showAdvancedOptions = $state(false);
	let logo = $state<File | null | undefined>();
	let darkLogo = $state<File | null | undefined>();
	let logoDataURL: string | null = $state(
		existingClient?.hasLogo ? cachedOidcClientLogo.getUrl(existingClient!.id) : null
	);
	let darkLogoDataURL: string | null = $state(
		existingClient?.hasDarkLogo ? cachedOidcClientLogo.getUrl(existingClient!.id, false) : null
	);

	const client = {
		id: '',
		name: existingClient?.name || '',
		description: existingClient?.description || '',
		callbackURLs: existingClient?.callbackURLs || [],
		logoutCallbackURLs: existingClient?.logoutCallbackURLs || [],
		isPublic: existingClient?.isPublic || false,
		pkceEnabled: existingClient?.pkceEnabled || false,
		requiresReauthentication: existingClient?.requiresReauthentication || false,
		requiresPushedAuthorizationRequests:
			existingClient?.requiresPushedAuthorizationRequests || false,
		skipConsent: existingClient?.skipConsent || false,
		launchURL: existingClient?.launchURL || '',
		forwardAuthEnabled: existingClient?.forwardAuthEnabled || false,
		forwardAuthExternalURL: existingClient?.forwardAuthExternalURL || '',
		forwardAuthUpstreamURL: existingClient?.forwardAuthUpstreamURL || '',
		forwardAuthInjectIdentityHeaders: existingClient?.forwardAuthInjectIdentityHeaders ?? true,
		forwardAuthUpstreamHeaders: existingClient?.forwardAuthUpstreamHeaders || [],
		credentials: {
			federatedIdentities: existingClient?.credentials?.federatedIdentities || []
		},
		logoUrl: '',
		darkLogoUrl: '',
		pkceSupported: existingClient?.pkceSupported || false
	};

	const formSchema = z
		.object({
			id: emptyToUndefined(
				z
					.string()
					.min(2)
					.max(128)
					.regex(/^[a-zA-Z0-9_-]+$/, {
						message: m.invalid_client_id()
					})
					.optional()
			),
			name: z.string().min(2).max(50),
			description: z.string().max(150),
			callbackURLs: z.array(callbackUrlSchema).default([]),
			logoutCallbackURLs: z.array(callbackUrlSchema).default([]),
			isPublic: z.boolean(),
			pkceEnabled: z.boolean(),
			requiresReauthentication: z.boolean(),
			requiresPushedAuthorizationRequests: z.boolean(),
			skipConsent: z.boolean(),
			launchURL: optionalUrl,
			forwardAuthEnabled: z.boolean(),
			forwardAuthExternalURL: optionalUrl,
			forwardAuthUpstreamURL: optionalUrl,
			forwardAuthInjectIdentityHeaders: z.boolean(),
			forwardAuthUpstreamHeaders: z
				.array(
					z.object({
						name: z.string(),
						value: z.string()
					})
				)
				.default([]),
			logoUrl: optionalUrl,
			darkLogoUrl: optionalUrl,
			credentials: z.object({
				federatedIdentities: z.array(
					z.object({
						issuer: z.url(),
						subject: z.string().optional(),
						audience: z.string().optional(),
						jwks: z.url().optional().or(z.literal('')),
						replayProtection: z.boolean().default(true)
					})
				)
			})
		})
		.superRefine((value, ctx) => {
			if (!value.forwardAuthEnabled || value.forwardAuthExternalURL) {
				return;
			}

			ctx.addIssue({
				code: 'custom',
				path: ['forwardAuthExternalURL'],
				message: m.forward_auth_external_url_required()
			});
		});

	type FormSchema = typeof formSchema;
	const { inputs, errors, ...form } = createForm<FormSchema>(formSchema, client);

	const pkcePromptNeeded = $derived(!$inputs.pkceEnabled.value && client.pkceSupported);

	async function onSubmit() {
		const data = form.validate();
		if (!data) return;
		isLoading = true;

		const success = await callback({
			...data,
			logo: $inputs.logoUrl?.value ? undefined : logo,
			logoUrl: $inputs.logoUrl?.value,
			darkLogo: $inputs.darkLogoUrl?.value ? undefined : darkLogo,
			darkLogoUrl: $inputs.darkLogoUrl?.value,
			isGroupRestricted: existingClient?.isGroupRestricted ?? true
		});

		const hasLogo = logo != null || !!$inputs.logoUrl?.value;
		const hasDarkLogo = darkLogo != null || !!$inputs.darkLogoUrl?.value;
		if (success && existingClient) {
			if (hasLogo) {
				logoDataURL = cachedOidcClientLogo.getUrl(existingClient.id);
			}
			if (hasDarkLogo) {
				darkLogoDataURL = cachedOidcClientLogo.getUrl(existingClient.id, false);
			}
		}

		if (success && !existingClient) form.reset();
		isLoading = false;
	}

	function onLogoChange(input: File | string | null, light: boolean = true) {
		if (input == null) return;

		const logoUrlInput = light ? $inputs.logoUrl : $inputs.darkLogoUrl;

		if (typeof input === 'string') {
			if (light) {
				logo = null;
				logoDataURL = input || null;
			} else {
				darkLogo = null;
				darkLogoDataURL = input || null;
			}
			logoUrlInput!.value = input;
		} else {
			if (light) {
				logo = input;
				logoDataURL = URL.createObjectURL(input);
			} else {
				darkLogo = input;
				darkLogoDataURL = URL.createObjectURL(input);
			}
			logoUrlInput && (logoUrlInput.value = '');
		}
	}

	function resetLogo(light: boolean = true) {
		if (light) {
			logo = null;
			logoDataURL = null;
			$inputs.logoUrl && ($inputs.logoUrl.value = '');
		} else {
			darkLogo = null;
			darkLogoDataURL = null;
			$inputs.darkLogoUrl && ($inputs.darkLogoUrl.value = '');
		}
	}

	function getFederatedIdentityErrors(errors: z.ZodError<any> | undefined) {
		return errors?.issues
			.filter((e) => e.path[0] == 'credentials' && e.path[1] == 'federatedIdentities')
			.map((e) => {
				e.path.splice(0, 2);
				return e;
			});
	}

	function addUpstreamHeader() {
		$inputs.forwardAuthUpstreamHeaders.value = [
			...$inputs.forwardAuthUpstreamHeaders.value,
			{ name: '', value: '' }
		];
	}

	function updateUpstreamHeader(index: number, field: keyof HTTPHeader, value: string) {
		$inputs.forwardAuthUpstreamHeaders.value = $inputs.forwardAuthUpstreamHeaders.value.map(
			(header, currentIndex) => (currentIndex === index ? { ...header, [field]: value } : header)
		);
	}

	function removeUpstreamHeader(index: number) {
		$inputs.forwardAuthUpstreamHeaders.value = $inputs.forwardAuthUpstreamHeaders.value.filter(
			(_, currentIndex) => currentIndex !== index
		);
	}
</script>

<form onsubmit={preventDefault(onSubmit)}>
	<div class="grid grid-cols-1 gap-x-3 gap-y-7 sm:flex-row md:grid-cols-2">
		<FormInput
			label={m.name()}
			class="w-full"
			description={m.client_name_description()}
			bind:input={$inputs.name}
		/>
		<FormInput
			label={m.client_description()}
			class="w-full"
			description={m.client_description_description()}
			bind:input={$inputs.description}
		/>
		<FormInput
			label={m.client_launch_url()}
			description={m.client_launch_url_description()}
			class="w-full"
			type="url"
			bind:input={$inputs.launchURL}
		/>
		<OidcCallbackUrlInput
			label={m.callback_urls()}
			description={m.callback_url_description()}
			class="w-full"
			bind:callbackURLs={$inputs.callbackURLs.value}
			bind:error={$inputs.callbackURLs.error}
		/>
		<OidcCallbackUrlInput
			label={m.logout_callback_urls()}
			description={m.logout_callback_url_description()}
			class="w-full"
			bind:callbackURLs={$inputs.logoutCallbackURLs.value}
			bind:error={$inputs.logoutCallbackURLs.error}
		/>
		<div class="md:col-span-2 rounded-xl border border-border/60 p-5">
			<div class="grid gap-5">
				<SwitchWithLabel
					id="forward-auth-enabled"
					label={m.forward_auth()}
					description={m.forward_auth_description()}
					bind:checked={$inputs.forwardAuthEnabled.value}
				/>
				{#if $inputs.forwardAuthEnabled.value}
					<div class="grid gap-5" transition:slide={{ duration: 200 }}>
						<div class="grid gap-4 lg:grid-cols-2">
							<FormInput
								label={m.forward_auth_external_url()}
								description={m.forward_auth_external_url_description()}
								class="w-full"
								type="url"
								bind:input={$inputs.forwardAuthExternalURL}
							/>
							<FormInput
								label="Forward Auth Upstream URL"
								description="Optional reverse proxy upstream. Set this to make Pocket ID behave like a proxy provider for the protected app."
								class="w-full"
								type="url"
								bind:input={$inputs.forwardAuthUpstreamURL}
							/>
						</div>
						<SwitchWithLabel
							id="forward-auth-inject-identity-headers"
							label="Inject Pocket ID Identity Headers"
							description="When enabled, Pocket ID adds X-Pocket-Id-* headers to the upstream request. Disable this if the legacy app should only receive your custom upstream headers."
							bind:checked={$inputs.forwardAuthInjectIdentityHeaders.value}
						/>
						<p class="text-muted-foreground text-sm">
							The existing "Skip Consent Screen" toggle also controls the forward-auth confirmation
							step. Disable "Skip Consent Screen" if you want users to confirm before Pocket ID
							continues to the protected app.
						</p>
						<div class="grid gap-4 rounded-lg border border-border/60 p-4">
							<div class="flex flex-wrap items-start justify-between gap-3">
								<div class="max-w-2xl">
									<p class="text-sm font-medium">Forward Auth Upstream Headers</p>
									<p class="text-muted-foreground text-sm">
										Static headers Pocket ID will inject to the upstream request, such as
										`X-API-Key` or `Authorization: Bearer ...`.
									</p>
								</div>
								<Button type="button" size="sm" variant="secondary" onclick={addUpstreamHeader}>
									Add Header
								</Button>
							</div>
							{#if $inputs.forwardAuthUpstreamHeaders.value.length > 0}
								<div class="grid gap-3">
									{#each $inputs.forwardAuthUpstreamHeaders.value as header, index}
										<div
											class="grid gap-3 rounded-lg border border-border/40 p-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.4fr)_auto] lg:items-end"
										>
											<div class="grid gap-2">
												<label class="text-sm font-medium" for={`header-name-${index}`}>
													Header Name
												</label>
												<Input
													id={`header-name-${index}`}
													value={header.name}
													oninput={(event) =>
														updateUpstreamHeader(
															index,
															'name',
															(event.currentTarget as HTMLInputElement).value
														)}
												/>
											</div>
											<div class="grid gap-2">
												<label class="text-sm font-medium" for={`header-value-${index}`}>
													Header Value
												</label>
												<Input
													id={`header-value-${index}`}
													value={header.value}
													oninput={(event) =>
														updateUpstreamHeader(
															index,
															'value',
															(event.currentTarget as HTMLInputElement).value
														)}
												/>
											</div>
											<Button
												type="button"
												size="sm"
												variant="ghost"
												class="justify-self-start lg:justify-self-end"
												onclick={() => removeUpstreamHeader(index)}
											>
												Remove
											</Button>
										</div>
									{/each}
								</div>
							{:else}
								<p class="text-muted-foreground text-sm">
									No custom upstream headers configured yet.
								</p>
							{/if}
						</div>
					</div>
				{/if}
			</div>
		</div>
		<SwitchWithLabel
			id="public-client"
			label={m.public_client()}
			description={m.public_clients_description()}
			onCheckedChange={(v) => {
				if (v) {
					$inputs.pkceEnabled.value = true;
				}
			}}
			bind:checked={$inputs.isPublic.value}
		/>
		<div
			class="rounded-lg transition-all duration-200"
			class:[&_[data-switch-root]]:ring-2={pkcePromptNeeded}
			class:[&_[data-switch-root]]:ring-blue-500={pkcePromptNeeded}
		>
			<SwitchWithLabel
				id="pkce"
				label={m.pkce()}
				description={m.proof_key_code_exchange_is_a_security_feature_to_prevent_csrf_and_authorization_code_interception_attacks()}
				disabled={$inputs.isPublic.value}
				bind:checked={$inputs.pkceEnabled.value}
			/>
		</div>
		<SwitchWithLabel
			id="requires-reauthentication"
			label={m.requires_reauthentication()}
			description={m.requires_users_to_authenticate_again_on_each_authorization()}
			bind:checked={$inputs.requiresReauthentication.value}
		/>
		<SwitchWithLabel
			id="skip-consent"
			label={m.skip_consent()}
			description={m.skip_consent_description()}
			bind:checked={$inputs.skipConsent.value}
		/>
	</div>
	<div class="mt-7 w-full md:w-1/2">
		<Tabs.Root value="light-logo">
			<Tabs.Content value="light-logo">
				<OidcClientImageInput
					{logoDataURL}
					resetLogo={() => resetLogo(true)}
					clientName={$inputs.name.value}
					light={true}
					onLogoChange={(input) => onLogoChange(input, true)}
				>
					{#snippet tabTriggers()}
						<Tabs.List class="grid h-8 w-full grid-cols-2">
							<Tabs.Trigger value="light-logo" class="px-3">
								<LucideSun class="size-4" />
							</Tabs.Trigger>
							<Tabs.Trigger value="dark-logo" class="px-3">
								<LucideMoon class="size-4" />
							</Tabs.Trigger>
						</Tabs.List>
					{/snippet}
				</OidcClientImageInput>
			</Tabs.Content>
			<Tabs.Content value="dark-logo">
				<OidcClientImageInput
					light={false}
					logoDataURL={darkLogoDataURL}
					resetLogo={() => resetLogo(false)}
					clientName={$inputs.name.value}
					onLogoChange={(input) => onLogoChange(input, false)}
				>
					{#snippet tabTriggers()}
						<Tabs.List class="grid h-8 w-full grid-cols-2">
							<Tabs.Trigger value="light-logo" class="px-3">
								<LucideSun class="size-4" />
							</Tabs.Trigger>
							<Tabs.Trigger value="dark-logo" class="px-3">
								<LucideMoon class="size-4" />
							</Tabs.Trigger>
						</Tabs.List>
					{/snippet}
				</OidcClientImageInput>
			</Tabs.Content>
		</Tabs.Root>
	</div>

	{#if showAdvancedOptions}
		<div class="mt-7 flex flex-col gap-y-7 md:col-span-2" transition:slide={{ duration: 200 }}>
			<SwitchWithLabel
				id="requires-par"
				label={m.requires_pushed_authorization_requests()}
				description={m.requires_pushed_authorization_requests_description()}
				bind:checked={$inputs.requiresPushedAuthorizationRequests.value}
			/>
			{#if mode == 'create'}
				<FormInput
					label={m.client_id()}
					placeholder={m.generated()}
					class="w-full md:w-1/2"
					description={m.custom_client_id_description()}
					bind:input={$inputs.id}
				/>
			{/if}
			<FederatedIdentitiesInput
				client={existingClient}
				bind:federatedIdentities={$inputs.credentials.value.federatedIdentities}
				errors={getFederatedIdentityErrors($errors)}
			/>
		</div>
	{/if}

	<div class="relative mt-5 flex justify-center">
		<Button
			variant="ghost"
			class="text-muted-foreground"
			onclick={() => (showAdvancedOptions = !showAdvancedOptions)}
		>
			{showAdvancedOptions ? m.hide_advanced_options() : m.show_advanced_options()}
			<LucideChevronDown
				class={cn(
					'size-5 transition-transform duration-200',
					showAdvancedOptions && 'rotate-180 transform'
				)}
			/>
		</Button>
		<Button {isLoading} type="submit" class="absolute right-0">{m.save()}</Button>
	</div>
</form>
