export type Theme = 'dark' | 'light';

const KEY = 'trawl.theme';

export function storedTheme(): Theme | null {
	const value = localStorage.getItem(KEY);
	return value === 'dark' || value === 'light' ? value : null;
}

export function systemTheme(): Theme {
	return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function applyTheme(theme: Theme): void {
	document.documentElement.dataset.theme = theme;
	localStorage.setItem(KEY, theme);

	const meta = document.querySelector('meta[name="theme-color"]');
	if (meta) meta.setAttribute('content', theme === 'light' ? '#eef2f1' : '#0f1417');
}
