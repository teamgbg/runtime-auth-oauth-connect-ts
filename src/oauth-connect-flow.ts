/**
 * @system runtime-auth-flow
 * @status handwritten
 */
/**
 * The generic redirect URI on scala-oauth-gateway-v3, resolved from its
 * `service_routing` row's `public_hostname`. The hostname+path must match
 * what's registered on each provider's OAuth client (Console/api-console
 * per provider) — the one operator step. Resolving from the registry keeps
 * the source free of literals; the registry is source-of-truth on our
 * side, the provider registration is the external mirror.
 *
 * Async + SWR-cached (per `hot-path-resolutions-are-cached`) — the OAuth
 * connect/callback paths await it.
 */

import { getAuthSecret, getEncryptionKey } from "@teamscala/runtime-auth-flow-config/configure";
import { makeServiceRoutingReader } from "@teamscala/db/registry/service-routing";
import { ServiceRoutingConfigSchema } from "@teamscala/registry-schemas/registry-schemas/service-routing";

const { resolveServicePublicUrl } = makeServiceRoutingReader(ServiceRoutingConfigSchema);

export const ROUTES = {
	connect: "/oauth/connect",
	callback: "/oauth/callback",
} as const;

export async function getOAuthRedirectUri(): Promise<string> {
	const base = await resolveServicePublicUrl("scala-oauth-gateway-v3");
	return `${base}/oauth/callback`;
}

export interface ProviderDef {
	kind: string;
	provider: string;
	authUrl?: string;
	tokenUrl?: string;
	userInfoUrl?: string;
	scope?: string[] | string;
	clientIdEnv?: string;
	clientSecretEnv?: string;
	tokenExchange?: "form" | "query";
	searchParams?: Record<string, string>;
}

export interface GenericTokens {
	accessToken: string;
	refreshToken?: string;
	expiresAt?: Date;
	scope?: string;
	/** Stable id for the connected account (oauth_connections.provider_account_id). */
	providerAccountId: string;
}

export interface GenericFlowDeps {
	/** Persist the tokens (e.g. encrypt + upsert an oauth_connections row). */
	onReady: (provider: string, organisationId: string, tokens: GenericTokens) => Promise<void>;
}

function scopeString(def: ProviderDef): string {
	const s = def.scope;
	return Array.isArray(s) ? s.join(" ") : s ?? "";
}

// OAuth state is HMAC-SIGNED, not bare base64 — a bare base64 blob was attacker-
// mintable (CRIT-1: an unauthenticated caller could start an OAuth flow pointed at
// any organisationId). The signature binds the state to this server's secret so a
// callback state can only have been produced by handleOAuthConnect on this host.
// Secret resolver follows the platform order (AUTH_SECRET → ENCRYPTION_KEY →
// SCALA_DEV_KEY) so the sign/verify path works on any service carrying any of the
// platform secrets (per service-boot/content-gate token.ts precedent).
import { timingSafeEqual } from "node:crypto";

function stateSecret(): string {
	return (
		getAuthSecret() ??
		getEncryptionKey() ??
		""
	);
}

/** Sign a callback state. Exported as the counterpart of `parseState`: the two
 *  form one signature pair, and keeping the signing half private made the pair
 *  untestable, which is why this security path carried no test at all. */
export function signState(
	provider: string,
	organisationId: string,
	callbackUrl: string,
): string {
	const payload = Buffer.from(
		JSON.stringify({ provider, organisationId, callbackUrl }),
	).toString("base64url");
	const sig = new Bun.CryptoHasher("sha256", stateSecret()).update(payload).digest("base64url");
	return `${payload}.${sig}`;
}

/** Verify the HMAC signature on a callback state and return the decoded payload.
 *  A state that fails signature verification (forged, tampered, or produced under
 *  a different secret) returns null — the caller 400s. */
export function parseState(
	state: string,
): { provider: string; organisationId: string; callbackUrl: string } | null {
	const idx = state.indexOf(".");
	if (idx === -1) return null;
	const payload = state.slice(0, idx);
	const sig = state.slice(idx + 1);
	const expected = new Bun.CryptoHasher("sha256", stateSecret())
		.update(payload)
		.digest("base64url");
	const a = Buffer.from(sig);
	const b = Buffer.from(expected);
	if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
	try {
		const parsed = JSON.parse(Buffer.from(payload, "base64url").toString()) as {
			provider: string;
			organisationId: string;
			callbackUrl: string;
		};
		if (parsed.provider && parsed.organisationId && parsed.callbackUrl) return parsed;
	} catch {
		// malformed payload (signature was valid but JSON wasn't — shouldn't happen)
	}
	return null;
}

function redirect(callbackUrl: string, success: boolean, error?: string): Response {
	let url: URL;
	try {
		url = new URL(callbackUrl);
	} catch {
		return new Response(success ? "Connected" : `Failed: ${error ?? "oauth_failed"}`, {
			status: success ? 200 : 400,
		});
	}
	url.searchParams.set(
		success ? "success" : "error",
		success ? "oauth_connected" : error || "oauth_failed",
	);
	return new Response(null, { status: 302, headers: { Location: url.toString() } });
}

/**
 * Step 1 — redirect the user to the provider's OAuth consent screen. The portal's
 * "connect <provider>" button hits /oauth/connect?provider=…&organisationId=…&callbackUrl=….
 */
export async function handleOAuthConnect(
	def: ProviderDef,
	organisationId: string,
	callbackUrl: string,
	creds: { clientId: string },
): Response {
	if (!def.authUrl || !def.clientIdEnv) {
		return new Response(`Provider ${def.provider} is not a configurable OAuth provider`, {
			status: 400,
		});
	}
	if (!organisationId || !callbackUrl) {
		return new Response("Missing required params: organisationId, callbackUrl", { status: 400 });
	}
	const url = new URL(def.authUrl);
	url.searchParams.set("client_id", creds.clientId);
	url.searchParams.set("redirect_uri", await getOAuthRedirectUri());
	url.searchParams.set("response_type", "code");
	const scope = scopeString(def);
	if (scope) url.searchParams.set("scope", scope);
	url.searchParams.set("state", signState(def.provider, organisationId, callbackUrl));
	for (const [key, value] of Object.entries(def.searchParams ?? {})) url.searchParams.set(key, value);
	return new Response(null, { status: 302, headers: { Location: url.toString() } });
}

interface TokenResponse {
	access_token?: string;
	refresh_token?: string;
	expires_in?: number;
	scope?: string;
	token_type?: string;
	user_id?: string;
	id_token?: string;
}

/**
 * Step 2 — the provider redirects back here with ?code=…&state=…. Exchange the
 * code for tokens (standard OAuth2 authorization-code grant; form body for most
 * providers, query string for Zoho), resolve the provider account id, then hand
 * the tokens to onReady for storage and redirect to the portal callback.
 */
export async function handleOAuthCallback(
	def: ProviderDef,
	code: string,
	state: string,
	creds: { clientId: string; clientSecret: string },
	deps: GenericFlowDeps,
): Promise<Response> {
	const parsed = parseState(state);
	if (!code || !parsed) return new Response("Missing or invalid code/state", { status: 400 });
	if (!def.tokenUrl) return new Response(`Provider ${def.provider} has no tokenUrl`, { status: 400 });

	const scope = scopeString(def);
	const params: Record<string, string> = {
		grant_type: "authorization_code",
		code,
		client_id: creds.clientId,
		client_secret: creds.clientSecret,
		redirect_uri: await getOAuthRedirectUri(),
	};
	if (scope) params.scope = scope;

	const tokenResp =
		def.tokenExchange === "query"
			? await fetch(`${def.tokenUrl}?${new URLSearchParams(params).toString()}`, { method: "POST" })
			: await fetch(def.tokenUrl, {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams(params).toString(),
				});
	if (!tokenResp.ok) {
		return redirect(parsed.callbackUrl, false, `token_exchange_failed_${tokenResp.status}`);
	}
	const tokens = (await tokenResp.json()) as TokenResponse;
	if (!tokens.access_token) return redirect(parsed.callbackUrl, false, "no_access_token");

	let providerAccountId = tokens.user_id ?? "default";
	if (def.userInfoUrl) {
		try {
			const userInfoResp = await fetch(def.userInfoUrl, {
				headers: { Authorization: `Bearer ${tokens.access_token}` },
			});
			if (userInfoResp.ok) {
				const userInfo = (await userInfoResp.json()) as {
					id?: string;
					sub?: string;
					Id?: string;
					user_id?: string;
				};
				providerAccountId = userInfo.id ?? userInfo.sub ?? userInfo.Id ?? userInfo.user_id ?? providerAccountId;
			}
		} catch {
			// userInfo is best-effort; a missing account id is non-fatal (falls back to "default").
		}
	}

	await deps.onReady(parsed.provider, parsed.organisationId, {
		accessToken: tokens.access_token,
		refreshToken: tokens.refresh_token,
		expiresAt: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : undefined,
		scope: tokens.scope ?? scope,
		providerAccountId,
	});
	return redirect(parsed.callbackUrl, true);
}
