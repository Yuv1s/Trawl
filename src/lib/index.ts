export const SCANNER_TOKEN_KEY = 'trawl.scanner.token';

export function getScannerToken(): string | null {
	return localStorage.getItem(SCANNER_TOKEN_KEY);
}

export function getOrCreateScannerToken(): string {
	const stored = getScannerToken();
	if (stored) return stored;

	const bytes = crypto.getRandomValues(new Uint8Array(32));
	const token = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
	localStorage.setItem(SCANNER_TOKEN_KEY, token);
	return token;
}
