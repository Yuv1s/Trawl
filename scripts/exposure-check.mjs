// Fails if the production build hands a browser something it should not have: source maps,
// secrets, private paths or addresses, debug calls, comments left for the next editor, or a
// page whose content security policy is missing or weaker than it should be.
//
//   npm run build && npm run exposure
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';

const BUILD = process.argv[2] ?? 'build';
const TEXT = new Set(['.html', '.js', '.css', '.json', '.svg', '.txt', '.md']);

const SECRETS = [
	['an AWS key', /AKIA[0-9A-Z]{16}/],
	['a GitHub token', /gh[pousr]_[A-Za-z0-9]{36}/],
	['a private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
	['an API key', /\bsk-[A-Za-z0-9_-]{32,}/],
	['a Slack token', /xox[baprs]-[A-Za-z0-9-]{20,}/]
];

const PRIVATE = [
	['a Windows user path', /[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+/],
	['a home directory', /\/(?:home|Users)\/[a-z0-9._-]+\/[A-Za-z.]/],
	['an email address', /[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|proton)\.[a-z]+/]
];

const DEBUG = [
	['a debugger statement', /\bdebugger;/],
	['a console.log call', /\bconsole\.(?:log|debug)\(/]
];

// Svelte's hydration markers and head anchors are the only comments a page should carry.
const COMMENT = /<!--(?!\[|\]|-*>|[a-z0-9]{5,9}-->)[\s\S]*?-->/;

// Every directive a page's policy must carry, and all each may allow. Nothing else may appear,
// since a browser would enforce a directive like script-src-elem over the ones checked here.
const POLICY = {
	'default-src': /^'self'$/,
	'object-src': /^'none'$/,
	'base-uri': /^'self'$/,
	'form-action': /^'self'$/,
	'font-src': /^'self'$/,
	'manifest-src': /^'self'$/,
	'script-src': /^'(?:self|wasm-unsafe-eval|sha256-[A-Za-z0-9+/]+=*)'$/,
	'style-src': /^'(?:self|unsafe-inline)'$/,
	'connect-src': /^(?:'self'|http:\/\/127\.0\.0\.1:\*|http:\/\/localhost:\*)$/,
	'img-src': /^(?:'self'|data:|blob:)$/,
	'worker-src': /^(?:'self'|blob:)$/
};

const unixLines = (text) => text.replaceAll('\r\n', '\n');

// A <meta> policy only covers what comes after it, so the only script allowed ahead of it is the
// shell's own, exactly as written by hand, and never something a build or a framework put there.
const SHELL_SCRIPTS = [
	...unixLines(readFileSync('src/app.html', 'utf8')).matchAll(/<script>([\s\S]*?)<\/script>/g)
].map((match) => match[1]);

// A browser only enforces a <meta> policy in the head, nothing ahead of it is held to it, and
// most else closes the head without saying so. So only these may come before it: plain metas,
// which fetch nothing, and scripts, which the check below holds to the shell's own.
const AHEAD_OF_POLICY =
	/^\s*(?:<!doctype html>\s*)?<html\b[^>]*>\s*<head\b[^>]*>\s*(?:(?:<meta\s+(?:charset|name)=[^>]*>|<script\b[^>]*>[\s\S]*?<\/script>)\s*)*$/i;

function policyProblems(html) {
	const tags = [...html.matchAll(/<meta http-equiv="content-security-policy" content="([^"]*)"/g)];
	if (tags.length !== 1) return [`${tags.length} content security policies, not one`];

	const problems = [];
	if (!AHEAD_OF_POLICY.test(html.slice(0, tags[0].index))) {
		problems.push('a policy outside the head, which a browser ignores');
	}

	const directives = new Map();
	for (const directive of tags[0][1].split(';')) {
		const [name, ...values] = directive.trim().split(/\s+/);
		if (!name) continue;
		// A browser keeps the first of a repeated directive, so a later one proves nothing.
		if (directives.has(name)) problems.push(`a policy repeating ${name}`);
		else directives.set(name, values);
	}

	for (const name of directives.keys()) {
		if (!(name in POLICY)) problems.push(`a policy with ${name}, which is not expected`);
	}
	for (const [name, allows] of Object.entries(POLICY)) {
		const values = directives.get(name) ?? [];
		if (values.length === 0) problems.push(`a policy with no ${name}`);
		for (const value of values) {
			if (!allows.test(value)) problems.push(`a policy allowing ${value} in ${name}`);
		}
	}

	const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
	for (const script of scripts) {
		const external = /\bsrc\s*=/i.test(script[1]);
		const body = script[2];

		if (script.index < tags[0].index) {
			if (external || !SHELL_SCRIPTS.includes(unixLines(body))) {
				problems.push('a script ahead of the policy');
			}
			continue;
		}
		if (external) continue;

		const hash = createHash('sha256').update(body).digest('base64');
		if (!directives.get('script-src')?.includes(`'sha256-${hash}'`)) {
			problems.push('an inline script the policy has no hash for');
		}
	}
	return problems;
}

// The samples are test data, and hold planted strings on purpose.
const isSample = (path) => relative(BUILD, path).startsWith('samples');

function* files(dir) {
	for (const name of readdirSync(dir)) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) yield* files(path);
		else yield path;
	}
}

const problems = [];
const report = (path, what) => problems.push(`${relative(BUILD, path)}: ${what}`);
let checked = 0;

for (const path of files(BUILD)) {
	if (isSample(path)) continue;
	checked += 1;

	const extension = extname(path).toLowerCase();
	if (extension === '.map') report(path, 'a source map');
	if (/(^|[\\/])\.env/.test(path)) report(path, 'an env file');

	// Compiled wasm is read for secrets too. Its panic messages name the paths it was built
	// from, which say nothing private on a build server and are not worth failing a local build.
	if (extension === '.wasm') {
		const bytes = readFileSync(path).toString('latin1');
		for (const [what, shape] of SECRETS) if (shape.test(bytes)) report(path, what);
		continue;
	}
	if (!TEXT.has(extension)) continue;

	const text = readFileSync(path, 'utf8');
	if (text.includes('sourceMappingURL')) report(path, 'a source map reference');
	for (const [what, shape] of [...SECRETS, ...PRIVATE, ...DEBUG]) {
		if (shape.test(text)) report(path, what);
	}
	if (extension === '.html') {
		if (COMMENT.test(text)) report(path, 'an HTML comment');
		for (const problem of policyProblems(text)) report(path, problem);
	}
}

if (checked === 0) {
	console.error('Nothing to check. Run npm run build first.');
	process.exit(1);
}

if (problems.length > 0) {
	console.error(`The build exposes ${problems.length} thing(s) it should not:`);
	for (const problem of problems) console.error(`  ${problem}`);
	process.exit(1);
}

console.log(`Checked ${checked} files. Nothing exposed.`);
