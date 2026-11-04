import { readSetting, removeSetting, writeSetting } from '$lib/settings';

export type TourChoice = 'tour' | 'skip';

const TOUR_CHOICE_KEY = 'trawl.tour.choice';

export function getTourChoice(): TourChoice | null {
	const value = readSetting(TOUR_CHOICE_KEY);
	return value === 'tour' || value === 'skip' ? value : null;
}

export function setTourChoice(choice: TourChoice): void {
	writeSetting(TOUR_CHOICE_KEY, choice);
}

export const SCANNER_TOKEN_KEY = 'trawl.scanner.token';
/** What this page generates. The token goes into a shell line the person pastes, so
 *  whatever else is stored here, by anything else this origin has served, is ignored. */
const TOKEN_SHAPE = /^[0-9a-f]{64}$/;
const ANALYSE_PREFIX = 'trawl.analyse.';

/** Where the scanner listens. The default is IPv4 because that is what the scanner
 *  binds, and `localhost` could reach some other program on the IPv6 loopback, which
 *  would then receive the token. */
export const SCANNER_URL = (import.meta.env.VITE_SCANNER_URL ?? 'http://127.0.0.1:8099').replace(
	/\/$/,
	''
);

/**
 * Remembers an address for the tab about to analyse it, and returns the one-time
 * code that tab carries. The address never goes in the link, so a link from another
 * site cannot make the scanner fetch anything: only this origin can write the entry.
 */
export function rememberAddress(address: string): string {
	const code = crypto.randomUUID();
	writeSetting(ANALYSE_PREFIX + code, address);
	return code;
}

/** Gives back a remembered address, once. */
export function takeAddress(code: string): string | null {
	const key = ANALYSE_PREFIX + code;
	const address = readSetting(key);
	removeSetting(key);
	return address;
}

export function getScannerToken(): string | null {
	const token = readSetting(SCANNER_TOKEN_KEY);
	return token && TOKEN_SHAPE.test(token) ? token : null;
}

export function getOrCreateScannerToken(): string {
	const stored = getScannerToken();
	if (stored) return stored;

	const bytes = crypto.getRandomValues(new Uint8Array(32));
	const token = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
	writeSetting(SCANNER_TOKEN_KEY, token);
	return token;
}
