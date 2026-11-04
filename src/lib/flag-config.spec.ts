import { describe, expect, it } from 'vitest';
import { DEFAULT_FLAG_TAGS, matchesFlagTag } from './flag-config';

describe('matchesFlagTag', () => {
	it('recognises an event name in front of a default ending', () => {
		for (const flag of ['testCTF{a}', 'DUCTF{a}', 'picoCTF{a}', 'flag{a}', 'HTB{a}']) {
			expect(matchesFlagTag(flag, DEFAULT_FLAG_TAGS)).toBe(true);
		}
	});

	it('still rejects a tag that ends in something else', () => {
		expect(matchesFlagTag('CTFtest{a}', DEFAULT_FLAG_TAGS)).toBe(false);
		expect(matchesFlagTag('iJ{eHzcJ}', DEFAULT_FLAG_TAGS)).toBe(false);
	});

	it('accepts any shape when the list is empty', () => {
		expect(matchesFlagTag('anything{a}', [])).toBe(true);
	});
});
