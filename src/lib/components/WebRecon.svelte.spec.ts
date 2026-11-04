import { page, userEvent } from 'vitest/browser';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { SCANNER_TOKEN_KEY } from '$lib';
import WebRecon from './WebRecon.svelte';

const TOKEN = 'a'.repeat(64);
const TARGET = 'http://localhost:5000/';

let unmount: (() => PromiseLike<void>) | undefined;

function scannerFetch(scanError: string, allowLocal = false) {
	return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
		const request = input instanceof Request ? input : null;
		const url = new URL(request?.url ?? input.toString());
		const method = init?.method ?? request?.method ?? 'GET';

		if (url.pathname === '/health') {
			return Response.json({ allow_local: allowLocal });
		}
		if (url.pathname === '/scan' && method === 'POST') {
			return new Response(scanError, { status: 400 });
		}

		throw new Error(`unexpected request: ${method} ${url}`);
	});
}

async function renderAndScan() {
	const view = await render(WebRecon, { onreset: vi.fn() });
	unmount = view.unmount;
	await expect.element(page.getByRole('heading', { name: 'Scanner connected' })).toBeVisible();
	await userEvent.fill(page.getByLabelText('Target URL'), TARGET);
	await page.getByRole('button', { name: 'Scan', exact: true }).click();
}

beforeEach(() => {
	localStorage.setItem(SCANNER_TOKEN_KEY, TOKEN);
});

afterEach(async () => {
	await unmount?.();
	unmount = undefined;
	localStorage.removeItem(SCANNER_TOKEN_KEY);
	vi.restoreAllMocks();
});

describe('WebRecon pairing token', () => {
	it('replaces a stored token that is not one this page generated', async () => {
		localStorage.setItem(SCANNER_TOKEN_KEY, "x'; echo INJECTED; echo '");
		vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no scanner'));

		const view = await render(WebRecon, { onreset: vi.fn() });
		unmount = view.unmount;

		const command = page.getByRole('textbox', { name: /scanner install command/i });
		await expect.element(command).toBeVisible();
		const value = (command.element() as HTMLInputElement).value;
		expect(value).not.toContain('INJECTED');
		expect(localStorage.getItem(SCANNER_TOKEN_KEY)).toMatch(/^[0-9a-f]{64}$/);
	});
});

describe('WebRecon scanner version', () => {
	const healthAnswering = (version: string) =>
		vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
			return Response.json({ allow_local: false, version });
		});

	it('warns about a scanner older than this page', async () => {
		healthAnswering('0.1.2');
		const view = await render(WebRecon, { onreset: vi.fn() });
		unmount = view.unmount;

		await expect.element(page.getByText(/this page expects 0\.1\.4/)).toBeVisible();
	});

	it('says nothing about a current scanner', async () => {
		healthAnswering('0.1.4');
		const view = await render(WebRecon, { onreset: vi.fn() });
		unmount = view.unmount;

		await expect.element(page.getByRole('heading', { name: 'Scanner connected' })).toBeVisible();
		expect(document.body.textContent).not.toContain('this page expects');
	});
});

describe('WebRecon scan results', () => {
	it('links only to web addresses, whatever the scanner answers', async () => {
		const hostile = 'javascript:alert(1)';
		const safe = 'https://example.test/page';
		vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
			const url = new URL(input instanceof Request ? input.url : input.toString());
			if (url.pathname === '/health')
				return Response.json({ allow_local: false, version: '0.1.2' });
			return Response.json({
				target: TARGET,
				pages: [],
				images: [],
				scripts: [],
				assets: [],
				external: [hostile, safe],
				found: [],
				flags: [],
				comments: []
			});
		});

		await renderAndScan();

		const opened = () => document.querySelector('.preview a.open');

		await page.getByRole('button', { name: hostile }).click();
		await expect.element(page.getByText('Open', { exact: true })).toBeVisible();
		expect(opened()?.hasAttribute('href')).toBe(false);

		await page.getByRole('button', { name: safe }).click();
		await expect.element(page.getByRole('link', { name: 'Open' })).toBeVisible();
		expect(opened()?.getAttribute('href')).toBe(safe);
	});
});

describe('WebRecon local restart', () => {
	it('copies a complete local-mode restart command after a loopback refusal', async () => {
		scannerFetch('refused: loopback (::1)');
		const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();

		await renderAndScan();

		const command = page.getByRole('textbox', { name: /local-mode restart command/i });
		await expect.element(command).toBeVisible();
		const commandValue = (command.element() as HTMLInputElement).value;
		expect(commandValue).toContain(TOKEN);
		expect(commandValue).toContain(window.location.origin);
		expect(commandValue).toContain("PORT='8099'");
		expect(commandValue).toContain('--allow-local');

		await page.getByRole('button', { name: 'Copy restart command' }).click();

		await expect.element(page.getByRole('button', { name: 'Copied' })).toBeVisible();
		await expect.element(page.getByRole('status')).toHaveTextContent('Restart command copied.');
		expect(writeText).toHaveBeenCalledOnce();
		expect(writeText.mock.calls[0][0]).toContain(TOKEN);
		expect(writeText.mock.calls[0][0]).toContain('--allow-local');
	});

	it('does not offer local mode for a link-local refusal', async () => {
		scannerFetch('refused: link-local, includes cloud metadata (169.254.0.0/16)');

		await renderAndScan();

		await expect.element(page.getByText(/includes cloud metadata/)).toBeVisible();
		await expect
			.element(page.getByRole('heading', { name: 'Restart in local mode' }))
			.not.toBeInTheDocument();
	});

	it('leaves the restart command selectable when clipboard access fails', async () => {
		scannerFetch('refused: loopback (::1)');
		vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('clipboard blocked'));

		await renderAndScan();
		await page.getByRole('button', { name: 'Copy restart command' }).click();

		await expect
			.element(page.getByText('Clipboard access failed. Select the command and copy it manually.'))
			.toBeVisible();
		await expect
			.element(page.getByRole('textbox', { name: /local-mode restart command/i }))
			.toBeVisible();
	});
});
