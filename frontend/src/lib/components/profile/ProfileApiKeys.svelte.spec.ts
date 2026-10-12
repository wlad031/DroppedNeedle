import { page } from '@vitest/browser/context';
import { describe, expect, it, vi } from 'vitest';
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
	revoke: vi.fn()
}));

vi.mock('@tanstack/svelte-query', () => ({
	createQuery: () => ({ data: h.keys, isLoading: false, isError: false }),
	createMutation: () => ({ mutateAsync: h.create, isPending: false })
}));
vi.mock('$lib/api/client', () => ({
	api: { global: { get: vi.fn(), post: vi.fn(), delete: vi.fn() } }
}));
vi.mock('$lib/queries/QueryClient', () => ({ invalidateQueriesWithPersister: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ toastStore: { show: vi.fn() } }));

import ProfileApiKeys from './ProfileApiKeys.svelte';

describe('ProfileApiKeys', () => {
	it('shows metadata without exposing a secret', async () => {
		await render(ProfileApiKeys);
		await expect.element(page.getByRole('heading', { name: 'API Keys' })).toBeVisible();
		await expect.element(page.getByText('Automation', { exact: true })).toBeVisible();
		await expect.element(page.getByText('catalog:read', { exact: false })).toBeVisible();
	});
});
