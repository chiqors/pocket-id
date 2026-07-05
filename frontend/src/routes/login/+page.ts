import OidcService from '$lib/services/oidc-service';
import type { OidcClientMetaData } from '$lib/types/oidc.type';
import type { PageLoad } from './$types';

function extractForwardAuthClientID(redirect: string, origin: string): string | null {
	try {
		const targetURL = new URL(redirect, origin);
		const pathPrefix = '/api/forward-auth/complete/';
		if (!targetURL.pathname.startsWith(pathPrefix)) {
			return null;
		}

		const clientID = targetURL.pathname.slice(pathPrefix.length).split('/')[0];
		return clientID ? decodeURIComponent(clientID) : null;
	} catch {
		return null;
	}
}

export const load: PageLoad = async ({ url }) => {
	const redirect = url.searchParams.get('redirect') || '/settings';
	const clientID = extractForwardAuthClientID(redirect, url.origin);

	let client: OidcClientMetaData | null = null;
	if (clientID) {
		try {
			const oidcService = new OidcService();
			client = await oidcService.getClientMetaData(clientID);
		} catch {
			client = null;
		}
	}

	return {
		redirect,
		client
	};
};
