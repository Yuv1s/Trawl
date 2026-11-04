import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const config = readFileSync('svelte.config.js', 'utf8');

describe('the content security policy', () => {
	it('never allows inline script', () => {
		const scripts = config.match(/'script-src': \[([^\]]*)\]/)?.[1];
		expect(scripts).toBeDefined();
		expect(scripts).not.toContain('unsafe-inline');
	});

	it('shows target images from blobs, without trusting the scanner as an image source', () => {
		const images = config.match(/'img-src': \[([^\]]*)\]/)?.[1];
		expect(images).toContain('blob:');
		expect(images).not.toContain('127.0.0.1');
		expect(images).not.toContain('localhost');
	});
});
