export type TourStep = {
	target: string;
	title: string;
	body: string;
	onenter?: () => void;
};
