<script lang="ts">
	import { beforeNavigate } from '$app/navigation';
	import { page } from '$app/state';
	import CollapsibleCard from '$lib/components/collapsible-card.svelte';
	import { openConfirmDialog } from '$lib/components/confirm-dialog';
	import CopyToClipboard from '$lib/components/copy-to-clipboard.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import * as Tabs from '$lib/components/ui/tabs';
	import UserGroupSelection from '$lib/components/user-group-selection.svelte';
	import { m } from '$lib/paraglide/messages';
	import OidcService from '$lib/services/oidc-service';
	import ScimService from '$lib/services/scim-service';
	import clientSecretStore from '$lib/stores/client-secret-store';
	import type { OidcClientCreateWithLogo } from '$lib/types/oidc.type';
	import type { ScimServiceProviderCreate } from '$lib/types/scim.type';
	import { cachedOidcClientLogo } from '$lib/utils/cached-image-util';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { LucideChevronLeft, LucideInfo, LucideRefreshCcw } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { slide } from 'svelte/transition';
	import { backNavigate } from '../../users/navigate-back-util';
	import OidcForm from '../oidc-client-form.svelte';
	import OidcClientPreviewModal from '../oidc-client-preview-modal.svelte';
	import ScimResourceProviderForm from './scim-resource-provider-form.svelte';

	let { data } = $props();
	let client = $state({
		...data.client,
		allowedUserGroupIds: data.client.allowedUserGroups.map((g) => g.id)
	});

	let scimServiceProvider = $state(data.scimServiceProvider);
	let showAllDetails = $state(false);
	let showPreview = $state(false);

	const oidcService = new OidcService();
	const scimService = new ScimService();
	const backNavigation = backNavigate('/settings/admin/oidc-clients');

	const setupDetails = $derived.by(() => ({
		[m.issuer_url()]: `https://${page.url.host}`,
		[m.authorization_url()]: `https://${page.url.host}/authorize`,
		[m.oidc_discovery_url()]: `https://${page.url.host}/.well-known/openid-configuration`,
		[m.token_url()]: `https://${page.url.host}/api/oidc/token`,
		[m.userinfo_url()]: `https://${page.url.host}/api/oidc/userinfo`,
		[m.logout_url()]: `https://${page.url.host}/api/oidc/end-session`,
		[m.certificate_url()]: `https://${page.url.host}/.well-known/jwks.json`,
		[m.pkce()]: client.pkceEnabled ? m.enabled() : m.disabled(),
		[m.requires_reauthentication()]: client.requiresReauthentication ? m.enabled() : m.disabled(),
		[m.requires_pushed_authorization_requests()]: client.requiresPushedAuthorizationRequests
			? m.enabled()
			: m.disabled(),
		[m.forward_auth()]: client.forwardAuthEnabled ? m.enabled() : m.disabled(),
		[m.forward_auth_external_url()]:
			client.forwardAuthExternalURL || m.forward_auth_external_url_not_configured()
	}));

	const forwardAuthHeaderNames = [
		'X-Pocket-Id-User-Id',
		'X-Pocket-Id-Username',
		'X-Pocket-Id-Name',
		'X-Pocket-Id-Display-Name',
		'X-Pocket-Id-Email',
		'X-Pocket-Id-Groups',
		'X-Pocket-Id-Is-Admin',
		'X-Pocket-Id-Client-Id'
	];

	function forwardAuthCaddySnippet() {
		const pocketIdBaseURL = page.url.origin;
		const clientId = encodeURIComponent(client.id);
		const copyHeaders = forwardAuthHeaderNames.join(' ');

		return `@pocket_id path /.pocket-id/*

handle @pocket_id {
\treverse_proxy ${pocketIdBaseURL}
}

route {
\tforward_auth ${pocketIdBaseURL} {
\t\turi /.pocket-id/auth/${clientId}
\t\tcopy_headers ${copyHeaders}
\t}

\treverse_proxy 127.0.0.1:3000 {
\t\theader_up -X-Pocket-Id-User-Id
\t\theader_up -X-Pocket-Id-Username
\t\theader_up -X-Pocket-Id-Name
\t\theader_up -X-Pocket-Id-Display-Name
\t\theader_up -X-Pocket-Id-Email
\t\theader_up -X-Pocket-Id-Groups
\t\theader_up -X-Pocket-Id-Is-Admin
\t\theader_up -X-Pocket-Id-Client-Id
\t}
}`;
	}

	function forwardAuthTraefikSnippet() {
		const pocketIdBaseURL = page.url.origin;
		const clientId = encodeURIComponent(client.id);
		const headerLines = forwardAuthHeaderNames.map((header) => `          - ${header}`).join('\n');

		return `http:
  routers:
    app:
      rule: Host(\`app.example.com\`)
      middlewares:
        - pocket-id-${clientId}
      service: app

    app-pocket-id:
      rule: Host(\`app.example.com\`) && PathPrefix(\`/.pocket-id/\`)
      priority: 100
      service: pocket-id

  middlewares:
    pocket-id-${clientId}:
      forwardAuth:
        address: ${pocketIdBaseURL}/.pocket-id/auth/${clientId}
        trustForwardHeader: true
        preserveLocationHeader: true
        authResponseHeaders:
${headerLines}

  services:
    pocket-id:
      loadBalancer:
        servers:
          - url: ${pocketIdBaseURL}

    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:3000`;
	}

	async function updateClient(updatedClient: OidcClientCreateWithLogo) {
		let success = true;
		const dataPromise = oidcService.updateClient(client.id, updatedClient);
		const imagePromise =
			updatedClient.logo !== undefined
				? oidcService.updateClientLogo(client, updatedClient.logo, true)
				: Promise.resolve();

		const darkImagePromise =
			updatedClient.darkLogo !== undefined
				? oidcService.updateClientLogo(client, updatedClient.darkLogo, false)
				: Promise.resolve();

		await Promise.all([dataPromise, imagePromise, darkImagePromise])
			.then(([updated]) => {
				if (updatedClient.logoUrl) {
					cachedOidcClientLogo.bustCache(client.id, true);
				}
				if (updatedClient.darkLogoUrl) {
					cachedOidcClientLogo.bustCache(client.id, false);
				}

				Object.assign(client, updated);

				// Update the hasLogo and hasDarkLogo flags after successful upload
				if (updatedClient.logo !== undefined || updatedClient.logoUrl !== undefined) {
					client.hasLogo = updatedClient.logo !== null || !!updatedClient.logoUrl;
				}
				if (updatedClient.darkLogo !== undefined || updatedClient.darkLogoUrl !== undefined) {
					client.hasDarkLogo = updatedClient.darkLogo !== null || !!updatedClient.darkLogoUrl;
				}
				toast.success(m.oidc_client_updated_successfully());
			})
			.catch((e) => {
				axiosErrorToast(e);
				success = false;
			});

		return success;
	}

	async function enableGroupRestriction() {
		client.isGroupRestricted = true;
		await oidcService
			.updateClient(client.id, {
				...client,
				isGroupRestricted: true
			})
			.then(() => {
				toast.success(m.user_groups_restriction_updated_successfully());
				client.isGroupRestricted = true;
			})
			.catch(axiosErrorToast);
	}

	function disableGroupRestriction() {
		openConfirmDialog({
			title: m.unrestrict_oidc_client({ clientName: client.name }),
			message: m.confirm_unrestrict_oidc_client_description({ clientName: client.name }),
			confirm: {
				label: m.unrestrict(),
				destructive: true,
				action: async () => {
					await oidcService
						.updateClient(client.id, {
							...client,
							isGroupRestricted: false
						})
						.then(() => {
							toast.success(m.user_groups_restriction_updated_successfully());
							client.allowedUserGroupIds = [];
							client.isGroupRestricted = false;
						})
						.catch(axiosErrorToast);
				}
			}
		});
	}

	async function createClientSecret() {
		openConfirmDialog({
			title: m.create_new_client_secret(),
			message: m.are_you_sure_you_want_to_create_a_new_client_secret(),
			confirm: {
				label: m.generate(),
				destructive: true,
				action: async () => {
					try {
						const clientSecret = await oidcService.createClientSecret(client.id);
						clientSecretStore.set(clientSecret);
						toast.success(m.new_client_secret_created_successfully());
					} catch (e) {
						axiosErrorToast(e);
					}
				}
			}
		});
	}

	async function updateUserGroupClients(allowedGroups: string[]) {
		await oidcService
			.updateAllowedUserGroups(client.id, allowedGroups)
			.then(() => {
				toast.success(m.allowed_user_groups_updated_successfully());
			})
			.catch((e) => {
				axiosErrorToast(e);
			});
	}

	async function saveScimServiceProvider(provider: ScimServiceProviderCreate | null) {
		try {
			if (!provider) {
				await scimService.deleteServiceProvider(scimServiceProvider!.id);
				scimServiceProvider = undefined;
				toast.success(m.scim_disabled_successfully());
				return true;
			}
			let createdProvider;
			if (scimServiceProvider) {
				createdProvider = await scimService.updateServiceProvider(scimServiceProvider.id, provider);
				toast.success(m.scim_configuration_updated_successfully());
			} else {
				createdProvider = await scimService.createServiceProvider(provider);
				toast.success(m.scim_enabled_successfully());
			}
			scimServiceProvider = createdProvider;
			return true;
		} catch (e) {
			axiosErrorToast(e);
			return false;
		}
	}

	beforeNavigate(() => {
		clientSecretStore.clear();
	});
</script>

<svelte:head>
	<title>{m.oidc_client_name({ name: client.name })}</title>
</svelte:head>

{#snippet UnrestrictButton()}
	<Button
		onclick={enableGroupRestriction}
		variant={client.isGroupRestricted ? 'secondary' : 'default'}>{m.restrict()}</Button
	>
{/snippet}

{#if client.pkceSupported && !client.pkceEnabled}
	<Alert.Root variant="info">
		<LucideInfo class="size-4" />
		<Alert.Title>{m.pkce_supported_client_title()}</Alert.Title>
		<Alert.Description>
			{m.pkce_supported_client_description()}
		</Alert.Description>
	</Alert.Root>
{/if}

<div>
	<button type="button" class="text-muted-foreground flex text-sm" onclick={backNavigation.go}
		><LucideChevronLeft class="size-5" /> {m.back()}</button
	>
</div>

<Card.Root>
	<Card.Header>
		<Card.Title>{client.name}</Card.Title>
	</Card.Header>
	<Card.Content>
		<div class="flex flex-col">
			<div class="mb-2 flex flex-col sm:flex-row sm:items-center">
				<Field.Label class="w-52">{m.client_id()}</Field.Label>
				<CopyToClipboard value={client.id}>
					<span class="text-muted-foreground text-sm" data-testid="client-id"> {client.id}</span>
				</CopyToClipboard>
			</div>
			{#if !client.isPublic}
				<div class="mt-1 mb-2 flex flex-col sm:flex-row sm:items-center">
					<Field.Label class="w-52">{m.client_secret()}</Field.Label>
					{#if $clientSecretStore}
						<CopyToClipboard value={$clientSecretStore}>
							<span class="text-muted-foreground text-sm" data-testid="client-secret">
								{$clientSecretStore}
							</span>
						</CopyToClipboard>
					{:else}
						<div>
							<span class="text-muted-foreground text-sm" data-testid="client-secret"
								>••••••••••••••••••••••••••••••••</span
							>
							<Button
								class="ml-2"
								onclick={createClientSecret}
								size="sm"
								variant="ghost"
								aria-label="Create new client secret"><LucideRefreshCcw class="size-3" /></Button
							>
						</div>
					{/if}
				</div>
			{/if}
			{#if showAllDetails}
				<div transition:slide>
					{#each Object.entries(setupDetails) as [key, value]}
						<div class="mb-2 flex flex-col sm:flex-row sm:items-center">
							<Field.Label class="w-52">{key}</Field.Label>
							<CopyToClipboard {value}>
								<span class="text-muted-foreground text-sm">{value}</span>
							</CopyToClipboard>
						</div>
					{/each}
				</div>
			{/if}

			{#if !showAllDetails}
				<div class="mt-4 flex justify-center">
					<Button onclick={() => (showAllDetails = true)} size="sm" variant="ghost"
						>{m.show_more_details()}</Button
					>
				</div>
			{/if}
		</div>
	</Card.Content>
</Card.Root>
<Card.Root>
	<Card.Content>
		<OidcForm mode="update" existingClient={client} callback={updateClient} />
	</Card.Content>
</Card.Root>
{#if client.forwardAuthEnabled && client.forwardAuthExternalURL}
	<Card.Root>
		<Card.Header>
			<Card.Title>{m.forward_auth_setup()}</Card.Title>
			<Card.Description>{m.forward_auth_setup_description()}</Card.Description>
		</Card.Header>
		<Card.Content>
			<Tabs.Root value="caddy">
				<Tabs.List class="grid w-full grid-cols-2">
					<Tabs.Trigger value="caddy">Caddy</Tabs.Trigger>
					<Tabs.Trigger value="traefik">Traefik</Tabs.Trigger>
				</Tabs.List>
				<Tabs.Content value="caddy" class="mt-4">
					<CopyToClipboard value={forwardAuthCaddySnippet()}>
						<pre class="bg-muted overflow-x-auto rounded-md p-4 text-xs">
{forwardAuthCaddySnippet()}</pre>
					</CopyToClipboard>
				</Tabs.Content>
				<Tabs.Content value="traefik" class="mt-4">
					<CopyToClipboard value={forwardAuthTraefikSnippet()}>
						<pre class="bg-muted overflow-x-auto rounded-md p-4 text-xs">
{forwardAuthTraefikSnippet()}</pre>
					</CopyToClipboard>
				</Tabs.Content>
			</Tabs.Root>
		</Card.Content>
	</Card.Root>
{/if}
<CollapsibleCard
	id="allowed-user-groups"
	title={m.allowed_user_groups()}
	button={!client.isGroupRestricted ? UnrestrictButton : undefined}
	forcedExpanded={client.isGroupRestricted ? undefined : false}
	description={client.isGroupRestricted
		? m.allowed_user_groups_description()
		: m.allowed_user_groups_status_unrestricted_description()}
>
	<UserGroupSelection
		bind:selectedGroupIds={client.allowedUserGroupIds}
		selectionDisabled={!client.isGroupRestricted}
	/>
	<div class="mt-5 flex justify-end gap-3">
		<Button onclick={disableGroupRestriction} variant="secondary">{m.unrestrict()}</Button>

		<Button usePromiseLoading onclick={() => updateUserGroupClients(client.allowedUserGroupIds)}
			>{m.save()}</Button
		>
	</div>
</CollapsibleCard>
<CollapsibleCard
	id="scim-provisioning"
	title={m.scim_provisioning()}
	description={m.scim_provisioning_description()}
>
	<ScimResourceProviderForm
		oidcClientId={client.id}
		existingProvider={scimServiceProvider}
		onSave={saveScimServiceProvider}
	/>
</CollapsibleCard>
<Card.Root>
	<Card.Header>
		<div class="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
			<div>
				<Card.Title>
					{m.oidc_data_preview()}
				</Card.Title>
				<Card.Description>
					{m.preview_the_oidc_data_that_would_be_sent_for_different_users()}
				</Card.Description>
			</div>

			<Button variant="outline" onclick={() => (showPreview = true)}>
				{m.show()}
			</Button>
		</div>
	</Card.Header>
</Card.Root>
<OidcClientPreviewModal bind:open={showPreview} clientId={client.id} />
