import { readSetting, writeSetting } from '$lib/settings';

export type Theme = 'dark' | 'light';

const KEY = 'trawl.theme';

export function storedTheme(): Theme | null {
	const value = readSetting(KEY);
	return value === 'dark' || value === 'light' ? value : null;
}

export function systemTheme(): Theme {
	return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

/** Applies a theme the person chose, and remembers it. */
export function applyTheme(theme: Theme): void {
	writeSetting(KEY, theme);
	showTheme(theme);
}

/** Applies a theme without storing it, so a visitor who never chose one keeps
 *  following their system setting. */
export function showTheme(theme: Theme): void {
	document.documentElement.dataset.theme = theme;

	const meta = document.querySelector('meta[name="theme-color"]');
	if (meta) meta.setAttribute('content', theme === 'light' ? '#eef2f1' : '#0f1417');
}
