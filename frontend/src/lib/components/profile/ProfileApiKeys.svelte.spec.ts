import { page } from '@vitest/browser/context';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';

const h = vi.hoisted(() => ({
	keys: {
		items: [
			{
				id: 'key-1',
				name: 'Automation',
				scopes: ['catalog:read'],
				created_at: '2026-01-01T00:00:00Z',
				expires_at: null,
				last_used_at: null
			}
		],
		cap: 25,
		active_count: 1
	},
	create: vi.fn(),
	revoke: vi.fn(),
	mutationCalls: 0
}));

vi.mock('@tanstack/svelte-query', () => ({
	createQuery: () => ({ data: h.keys, isLoading: false, isError: false }),
	createMutation: () => ({ mutateAsync: h.mutationCalls++ === 0 ? h.create : h.revoke, isPending: false })
}));
vi.mock('$lib/api/client', () => ({
	api: { global: { get: vi.fn(), post: vi.fn(), delete: vi.fn() } }
}));
vi.mock('$lib/queries/QueryClient', () => ({ invalidateQueriesWithPersister: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ toastStore: { show: vi.fn() } }));

import ProfileApiKeys from './ProfileApiKeys.svelte';

describe('ProfileApiKeys', () => {
	beforeEach(() => {
		h.create.mockReset();
		h.revoke.mockReset();
		h.mutationCalls = 0;
	});

	it('shows metadata without exposing a secret', async () => {
		await render(ProfileApiKeys);
		await expect.element(page.getByRole('heading', { name: 'API Keys' })).toBeVisible();
		await expect.element(page.getByText('Automation', { exact: true })).toBeVisible();
		await expect.element(page.getByText('catalog:read', { exact: false })).toBeVisible();
		await expect.element(page.getByText('dnk_', { exact: false })).not.toBeInTheDocument();
	});

	it('creates a key with expiry and reveals it once for copying', async () => {
		h.create.mockResolvedValue({
			key: 'dnk_key_secret',
			api_key: h.keys.items[0]
		});
		await render(ProfileApiKeys);
		await page.getByLabelText('API key name').fill('Nightly sync');
		await page.getByLabelText('Expiry (optional)').fill('2026-12-31T23:59');
		await page.getByRole('button', { name: /Create key/ }).click();
		await expect.element(page.getByText('dnk_key_secret', { exact: true })).toBeVisible();
		expect(h.create).toHaveBeenCalledWith(
			expect.objectContaining({
				name: 'Nightly sync',
				scopes: ['catalog:read'],
				expires_at: expect.stringMatching(/Z$/)
			})
		);
		await page.getByRole('button', { name: "I've saved it" }).click();
		await expect.element(page.getByText('dnk_key_secret', { exact: true })).not.toBeInTheDocument();
	});

	it('confirms and revokes a listed key', async () => {
		h.revoke.mockResolvedValue(undefined);
		await render(ProfileApiKeys);
		await page.getByRole('button', { name: 'Revoke Automation' }).click();
		await expect.element(page.getByText('Revoke “Automation”? This takes effect immediately.')).toBeVisible();
		await page.getByRole('button', { name: 'Revoke', exact: true }).click();
		expect(h.revoke).toHaveBeenCalledWith('key-1');
	});
});
