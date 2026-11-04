/** Each distinct value the items carry, with the first item that carried it, in that order. */
export function firstOfEach<T, V>(items: T[], valuesOf: (item: T) => V[] | undefined): [V, T][] {
	const seen = new Map<V, T>();
	for (const item of items) {
		for (const value of valuesOf(item) ?? []) {
			if (!seen.has(value)) seen.set(value, item);
		}
	}
	return [...seen];
}

/**
 * How many items each key had, and the items themselves up to `limit` of each key, both in
 * the order they came. An item with no key counts for nothing.
 */
export function tally<T>(
	items: T[],
	keyOf: (item: T) => string | null | undefined,
	limit = Infinity
): { kept: T[]; counts: Map<string, number> } {
	const counts = new Map<string, number>();
	const kept: T[] = [];
	for (const item of items) {
		const key = keyOf(item);
		if (key === null || key === undefined) continue;
		const before = counts.get(key) ?? 0;
		counts.set(key, before + 1);
		if (before < limit) kept.push(item);
	}
	return { kept, counts };
}
