/**
 * @system runtime-auth-flow
 * @status handwritten
 */
import { decrypt } from "@teamscala/encryption/crypto/decrypt";
import { getGoogleOAuthClientCredentials } from "@teamscala/google-workspace-configure/configure";
import { loadRegistryConfig } from "@teamscala/db/registry/load-config";
import * as v from "valibot";
import type { ProviderDef } from "./oauth-connect-flow.ts";

interface OauthProviderDefs {
	providers: ProviderDef[];
}

export async function loadProviderDefs(): Promise<ProviderDef[]> {
	const cfg = (await loadRegistryConfig(
		"config",
		"oauth-provider-definitions",
		v.unknown(),
	)) as OauthProviderDefs;
	return cfg.providers.filter((p) => p.kind === "oauth");
}

export async function findProviderDef(provider: string): Promise<ProviderDef | undefined> {
	return (await loadProviderDefs()).find((p) => p.provider === provider);
}

export async function resolveCreds(def: ProviderDef): Promise<{ clientId: string; clientSecret: string }> {
	if (def.provider === "google") {
		const { clientId, clientSecret } = getGoogleOAuthClientCredentials();
		if (!clientId || !clientSecret) {
			throw new Error("Google OAuth client credentials not configured (google-workspace)");
		}
		return { clientId, clientSecret };
	}
	const family = def.provider.startsWith("zoho") ? "zoho" : def.provider;
	const slug = `${family}-oauth-client`;
	const row = (await loadRegistryConfig("secret", slug, v.unknown())) as {
		clientId?: string;
		clientSecret?: string;
		token?: string;
	};
	const clientId = row.clientId;
	const clientSecret = def.provider.startsWith("zoho")
		? row.token
			? decrypt(row.token)
			: undefined
		: row.clientSecret;
	if (!clientId || !clientSecret) {
		throw new Error(`${def.provider} OAuth client credentials not configured (secret/${slug})`);
	}
	return { clientId, clientSecret };
}
