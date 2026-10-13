<script lang="ts">
	import { Copy, KeyRound, Plus, Trash2 } from 'lucide-svelte';
	import { createMutation, createQuery } from '@tanstack/svelte-query';
	import { api } from '$lib/api/client';
	import { API, CACHE_TTL } from '$lib/constants';
	import { invalidateQueriesWithPersister } from '$lib/queries/QueryClient';
	import { toastStore } from '$lib/stores/toast';
	import type {
		ApiKeyCreateResponse,
		ApiKeyListResponse,
		ApiKeyScope,
		ApiKeyView
	} from '$lib/types';

	const queryKey = ['profile', 'api-keys'];
	const keys = createQuery(() => ({
		queryKey,
		staleTime: CACHE_TTL.LIBRARY_NATIVE,
		queryFn: ({ signal }) => api.global.get<ApiKeyListResponse>(API.apiKeys.list(), { signal })
	}));
	const create = createMutation(() => ({
		mutationFn: (body: { name: string; scopes: ApiKeyScope[]; expires_at: string | null }) =>
			api.global.post<ApiKeyCreateResponse>(API.apiKeys.list(), body),
		onSuccess: () => invalidateQueriesWithPersister({ queryKey })
	}));
	const revoke = createMutation(() => ({
		mutationFn: (id: string) => api.global.delete<void>(API.apiKeys.item(id)),
		onSuccess: () => invalidateQueriesWithPersister({ queryKey })
	}));

	const scopeOptions: { value: ApiKeyScope; label: string }[] = [
		{ value: 'catalog:read', label: 'Catalog read' },
		{ value: 'requests:read', label: 'Requests read' },
		{ value: 'requests:write', label: 'Requests write' },
		{ value: 'playlists:read', label: 'Playlists read' },
		{ value: 'playlists:write', label: 'Playlists write' },
		{ value: 'scrobble:write', label: 'Scrobble write' }
	];
	let name = $state('');
	let selected = $state<ApiKeyScope[]>(['catalog:read']);
	let expiry = $state('');
	let revealed = $state<string | null>(null);
	let pending = $state<ApiKeyView | null>(null);

	async function createKey() {
		if (!name.trim() || selected.length === 0) return;
		try {
			const result = await create.mutateAsync({
				name: name.trim(),
				scopes: selected,
				expires_at: expiry ? new Date(expiry).toISOString() : null
			});
			revealed = result.key;
			name = '';
			expiry = '';
		} catch {
			toastStore.show({ message: 'Could not create API key', type: 'error' });
		}
	}
	async function copy(value: string) {
		try {
			await navigator.clipboard.writeText(value);
			toastStore.show({ message: 'Copied', type: 'success' });
		} catch {
			toastStore.show({ message: 'Could not copy', type: 'error' });
		}
	}
	async function confirmRevoke() {
		if (!pending) return;
		try {
			await revoke.mutateAsync(pending.id);
			toastStore.show({ message: 'API key revoked', type: 'success' });
		} catch {
			toastStore.show({ message: 'Could not revoke API key', type: 'error' });
		} finally {
			pending = null;
		}
	}
</script>

<section class="space-y-4">
	<div class="flex items-center gap-2">
		<KeyRound class="h-4 w-4 text-accent" />
		<h2 class="text-sm font-semibold uppercase tracking-widest text-base-content/50">API Keys</h2>
	</div>
	<p class="text-sm text-base-content/70">
		Automation keys only access the scopes you select. They cannot stream media, change settings, or
		administer the server.
	</p>
	{#if revealed}<div class="alert alert-warning">
			<span class="font-mono break-all">{revealed}</span><button
				class="btn btn-sm"
				onclick={() => copy(revealed!)}><Copy class="h-4 w-4" /> Copy</button
			><button class="btn btn-sm" onclick={() => (revealed = null)}>I've saved it</button>
		</div>{/if}
	<form
		class="rounded-xl border border-base-300 p-4 space-y-3"
		onsubmit={(e) => {
			e.preventDefault();
			void createKey();
		}}
	>
		<input
			class="input input-bordered w-full"
			bind:value={name}
			placeholder="Key name"
			aria-label="API key name"
		/>
		<div class="grid gap-2 sm:grid-cols-2">
			{#each scopeOptions as option (option.value)}<label
					class="label cursor-pointer justify-start gap-2"
					><input
						class="checkbox checkbox-sm"
						type="checkbox"
						checked={selected.includes(option.value)}
						onchange={(e) => {
							selected = e.currentTarget.checked
								? [...selected, option.value]
								: selected.filter((x) => x !== option.value);
						}}
					/>{option.label}</label
				>{/each}
		</div>
		<label class="form-control"
			><span class="label-text">Expiry (optional)</span><input
				class="input input-bordered"
				type="datetime-local"
				bind:value={expiry}
			/></label
		>
		<button class="btn btn-primary" disabled={create.isPending}
			><Plus class="h-4 w-4" />Create key</button
		>
	</form>
	{#if keys.isLoading}<div class="skeleton h-24 w-full"></div>{:else if keys.isError}<div
			class="alert alert-error"
		>
			Couldn't load API keys.
		</div>{:else}<div class="space-y-2">
			{#each keys.data?.items ?? [] as key (key.id)}<div
					class="flex items-center justify-between rounded-xl border border-base-300 p-3"
				>
					<div>
						<div class="font-medium">{key.name}</div>
						<div class="text-xs text-base-content/60">
							{key.scopes.join(', ')} · expires {key.expires_at
								? new Date(key.expires_at).toLocaleDateString()
								: 'never'}
						</div>
					</div>
					<button
						class="btn btn-ghost btn-sm text-error"
						aria-label={`Revoke ${key.name}`}
						onclick={() => (pending = key)}><Trash2 class="h-4 w-4" /></button
					>
				</div>{:else}<p class="text-sm text-base-content/60">No API keys yet.</p>{/each}
		</div>{/if}
	{#if pending}<div class="alert">
			<span>Revoke “{pending.name}”? This takes effect immediately.</span><button
				class="btn btn-error btn-sm"
				onclick={() => void confirmRevoke()}>Revoke</button
			><button class="btn btn-ghost btn-sm" onclick={() => (pending = null)}>Cancel</button>
		</div>{/if}
</section>
