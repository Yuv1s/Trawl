import { page } from 'vitest/browser';
import { afterEach, describe, expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import type { Found } from '$lib/worker/protocol';
import Recovered from './Recovered.svelte';
import StringsView from './StringsView.svelte';
import SweepView from './SweepView.svelte';

// Files repeat themselves, and a repeated value used as an each-block key stops the
// whole page from rendering. These are the shapes real files produced.
describe('repeated values from a file', () => {
	let unmount: (() => PromiseLike<void>) | undefined;

	afterEach(async () => {
		await unmount?.();
		unmount = undefined;
	});

	it('shows a flag the sweep read twice once', async () => {
		const view = await render(SweepView, {
			rows: [
				{
					title: 'rgb',
					chips: [],
					reason: 'flag-shaped string',
					preview: 'flag{twice}flag{twice}',
					readable: 22,
					flags: ['flag{twice}', 'flag{twice}'],
					onextract: () => {}
				}
			],
			combinations: 84,
			over: '100 pixels',
			blocked: '',
			error: null,
			extracted: null
		});
		unmount = view.unmount;

		await expect.element(page.getByText('flag{twice}', { exact: true })).toBeVisible();
		expect(document.querySelectorAll('.flags li').length).toBe(1);
	});

	it('shows two flags from one offset', async () => {
		const view = await render(Recovered, {
			candidates: [
				{ offset: 40, text: 'flag{one}' },
				{ offset: 40, text: 'flag{two}' }
			],
			sources: { 40: 'inside zTXt' }
		});
		unmount = view.unmount;

		await expect.element(page.getByText('flag{one}')).toBeVisible();
		await expect.element(page.getByText('flag{two}')).toBeVisible();
	});

	it('lists strings that share an offset', async () => {
		const sample: Found[] = [
			{ offset: 8, text: 'same place' },
			{ offset: 8, text: 'same place, wide' }
		];
		const view = await render(StringsView, { total: 2, sample });
		unmount = view.unmount;

		await expect.element(page.getByText('same place, wide')).toBeVisible();
		expect(document.querySelectorAll('ul li').length).toBe(2);
	});
});
