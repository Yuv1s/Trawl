export type TourChoice = 'tour' | 'skip';

const TOUR_CHOICE_KEY = 'trawl.tour.choice';

export function getTourChoice(): TourChoice | null {
	const value = localStorage.getItem(TOUR_CHOICE_KEY);
	return value === 'tour' || value === 'skip' ? value : null;
}

export function setTourChoice(choice: TourChoice): void {
	localStorage.setItem(TOUR_CHOICE_KEY, choice);
}

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
