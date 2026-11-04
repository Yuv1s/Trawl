const FOCUSABLE =
	'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Keeps Tab inside a modal dialog, and returns focus to where it was on close. */
export function trapFocus(dialog: HTMLElement): () => void {
	const previous = document.activeElement as HTMLElement | null;

	function keydown(event: KeyboardEvent) {
		if (event.key !== 'Tab') return;

		const items = [...dialog.querySelectorAll<HTMLElement>(FOCUSABLE)];
		const first = items[0] ?? dialog;
		const last = items[items.length - 1] ?? dialog;
		const active = document.activeElement;

		if (!dialog.contains(active)) {
			event.preventDefault();
			first.focus();
		} else if (event.shiftKey && (active === first || active === dialog)) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && active === last) {
			event.preventDefault();
			first.focus();
		}
	}

	document.addEventListener('keydown', keydown);
	return () => {
		document.removeEventListener('keydown', keydown);
		if (previous?.isConnected) previous.focus();
	};
}
