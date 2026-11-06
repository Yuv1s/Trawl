import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const config = readFileSync('vite.config.ts', 'utf8');

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

const FRAMEWORK = '{ __sveltekit = {}; }';
const hashOf = (body: string) => createHash('sha256').update(body).digest('base64');

const policy = (scriptSrc = `'self' 'wasm-unsafe-eval' 'sha256-${hashOf(FRAMEWORK)}'`) =>
	[
		`default-src 'self'`,
		`worker-src 'self' blob:`,
		`connect-src 'self' http://127.0.0.1:*`,
		`font-src 'self'`,
		`img-src 'self' data: blob:`,
		`manifest-src 'self'`,
		`object-src 'none'`,
		`script-src ${scriptSrc}`,
		`style-src 'self' 'unsafe-inline'`,
		`base-uri 'self'`,
		`form-action 'self'`
	].join('; ');

const meta = (content: string) =>
	`<meta http-equiv="content-security-policy" content="${content}" />`;

const page = (head: string, body = `<script>${FRAMEWORK}</script>`) =>
	`<!doctype html><html><head>${head}</head><body>${body}</body></html>`;

const shellScript = () => {
	const shell = readFileSync('src/app.html', 'utf8').match(/<script>[\s\S]*?<\/script>/)?.[0];
	if (!shell) throw new Error('src/app.html has no script');
	return shell;
};

const shellBody = () => shellScript().replace(/^<script>|<\/script>$/g, '');

/** What the build check says about a build holding only this page, empty if it passes. */
function exposure(html: string): string {
	const build = mkdtempSync(join(tmpdir(), 'trawl-exposure-'));
	try {
		writeFileSync(join(build, 'index.html'), html);
		execFileSync(process.execPath, ['scripts/exposure-check.mjs', build], { stdio: 'pipe' });
		return '';
	} catch (error) {
		return String((error as { stderr: Buffer }).stderr);
	} finally {
		rmSync(build, { recursive: true, force: true });
	}
}

describe('the build check on the policy a page was given', () => {
	it('passes a page holding the policy, with the shell script ahead of it', () => {
		expect(exposure(page(`${shellScript()}${meta(policy())}`))).toBe('');
	});

	it.each([
		['no policy at all', page(''), '0 content security policies'],
		['two policies', page(`${meta(policy())}${meta(policy())}`), '2 content security policies'],
		[
			'inline script allowed',
			page(meta(policy(`'self' 'unsafe-inline'`)), ''),
			"allowing 'unsafe-inline' in script-src"
		],
		[
			'eval allowed',
			page(meta(policy(`'self' 'unsafe-eval'`)), ''),
			"allowing 'unsafe-eval' in script-src"
		],
		[
			'scripts from anywhere',
			page(meta(policy(`'self' https:`)), ''),
			'allowing https: in script-src'
		],
		[
			'connections to anywhere',
			page(meta(policy().replace('http://127.0.0.1:*', '*'))),
			'allowing * in connect-src'
		],
		[
			'plugins allowed',
			page(meta(policy().replace(`object-src 'none'`, `object-src 'self'`))),
			"allowing 'self' in object-src"
		],
		[
			'a directive left out',
			page(meta(policy().replace(`base-uri 'self'; `, ''))),
			'a policy with no base-uri'
		],
		[
			'a weak directive ahead of a strong one',
			page(meta(`script-src 'unsafe-inline'; ${policy()}`)),
			'a policy repeating script-src'
		],
		[
			'a directive that overrides script-src for elements',
			page(meta(`${policy()}; script-src-elem *`)),
			'script-src-elem, which is not expected'
		],
		[
			'a directive that overrides script-src for attributes',
			page(meta(`${policy()}; script-src-attr 'unsafe-inline'`)),
			'script-src-attr, which is not expected'
		],
		[
			'an inline script with no hash',
			page(meta(policy()), '<script>alert(1)</script>'),
			'an inline script the policy has no hash for'
		],
		[
			'an inline script ahead of the policy',
			page(`<script>alert(1)</script>${meta(policy())}`),
			'a script ahead of the policy'
		],
		[
			'an external script ahead of the policy',
			page(`<script src="https://evil.example/x.js"></script>${meta(policy())}`),
			'a script ahead of the policy'
		],
		[
			'part of the shell script ahead of the policy',
			page(`${shellScript().replace('var stored = null;', '')}${meta(policy())}`),
			'a script ahead of the policy'
		],
		[
			'an external script written in capitals ahead of the policy',
			page(`<SCRIPT SRC = "https://evil.example/x.js">${shellBody()}</SCRIPT>${meta(policy())}`),
			'a script ahead of the policy'
		],
		[
			'an inline script written in capitals with no hash',
			page(meta(policy()), '<SCRIPT>alert(1)</SCRIPT>'),
			'an inline script the policy has no hash for'
		],
		[
			'the policy in the body',
			`<!doctype html><html><head></head><body>${meta(policy())}</body></html>`,
			'a policy outside the head'
		],
		[
			'the policy in a template',
			page(`<template>${meta(policy())}</template>`),
			'a policy outside the head'
		],
		[
			'an element ahead of the policy that closes the head',
			page(`<main></main>${meta(policy())}`),
			'a policy outside the head'
		],
		[
			'text ahead of the policy that closes the head',
			page(`stray text${meta(policy())}`),
			'a policy outside the head'
		],
		[
			'a stylesheet ahead of the policy',
			page(`<link rel="stylesheet" href="https://evil.example/x.css" />${meta(policy())}`),
			'a policy outside the head'
		],
		[
			'a redirect ahead of the policy',
			page(`<meta http-equiv="refresh" content="0;url=https://evil.example" />${meta(policy())}`),
			'a policy outside the head'
		],
		[
			'the policy in a noscript',
			page(`<noscript>${meta(policy())}</noscript>`),
			'a policy outside the head'
		],
		[
			'an empty script ahead of the policy',
			page(`<script></script>${meta(policy())}`),
			'a script ahead of the policy'
		]
	])('fails a page with %s', (_, html, says) => {
		expect(exposure(html)).toContain(says);
	});
});
