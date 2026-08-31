const FLAG_TAGS_KEY = 'trawl.flag.tags';

export const DEFAULT_FLAG_TAGS = ['flag', 'CTF', 'key', 'HTB', 'THM', 'picoCTF'];

function clean(tags: string[]): string[] {
	const unique = new Map<string, string>();
	for (const raw of tags) {
		const tag = raw.trim();
		if (!/^[A-Za-z0-9_]{2,20}$/.test(tag)) continue;
		unique.set(tag.toLowerCase(), tag);
	}
	return [...unique.values()];
}

export function readFlagTags(): string[] {
	try {
		const stored = localStorage.getItem(FLAG_TAGS_KEY);
		if (!stored) return [...DEFAULT_FLAG_TAGS];
		const parsed = JSON.parse(stored);
		return Array.isArray(parsed)
			? clean(parsed.filter((value): value is string => typeof value === 'string'))
			: [...DEFAULT_FLAG_TAGS];
	} catch {
		return [...DEFAULT_FLAG_TAGS];
	}
}

export function writeFlagTags(tags: string[]): string[] {
	const next = clean(tags);
	try {
		localStorage.setItem(FLAG_TAGS_KEY, JSON.stringify(next));
	} catch {
		return next;
	}
	return next;
}

export function matchesFlagTag(text: string, tags: string[]): boolean {
	const tag = text.split('{', 1)[0]?.toLowerCase() ?? '';
	return tags.length === 0 || tags.some((known) => known.toLowerCase() === tag);
}

export function flagTagsParameter(tags: string[]): string {
	return clean(tags).join(',');
}
