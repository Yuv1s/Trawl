/** localStorage throws in a browser that blocks site data, and a preference is
 *  never worth breaking the page over. Without storage, settings last for the
 *  visit and no longer. */
export function readSetting(key: string): string | null {
	try {
		return localStorage.getItem(key);
	} catch {
		return null;
	}
}

export function writeSetting(key: string, value: string): void {
	try {
		localStorage.setItem(key, value);
	} catch {
		// Nothing to do: the setting holds for this visit only.
	}
}

export function removeSetting(key: string): void {
	try {
		localStorage.removeItem(key);
	} catch {
		// Blocked storage never held the value in the first place.
	}
}
