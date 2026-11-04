import { afterEach, describe, expect, it } from 'vitest';
import { encodePng } from '$lib/pixels/png-encode';
import AnalysisWorker from './analysis.worker?worker';
import type { AnalysisRequest, AnalysisResponse } from './protocol';

const WIDTH = 8;
const HEIGHT = 16;
const HEIGHT_OFFSET = 20;

function pngWithFalseHeight(): Uint8Array {
	const png = encodePng(WIDTH, HEIGHT, 2, new Uint8Array(WIDTH * HEIGHT * 3).fill(120));
	new DataView(png.buffer, png.byteOffset).setUint32(HEIGHT_OFFSET, HEIGHT / 2);
	return png;
}

describe('the analysis worker', () => {
	let worker: Worker;

	function send(request: AnalysisRequest): Promise<AnalysisResponse> {
		return new Promise((resolve, reject) => {
			worker.onerror = (event) => reject(new Error(event.message));
			worker.onmessage = (event: MessageEvent<AnalysisResponse>) => resolve(event.data);
			worker.postMessage(request);
		});
	}

	afterEach(() => worker.terminate());

	it('repairs a PNG whose header lies about its height, then reads it cleanly', async () => {
		worker = new AnalysisWorker();
		const broken = pngWithFalseHeight();

		const first = await send({
			kind: 'analyse',
			id: 1,
			name: 'cut.png',
			bytes: broken.slice().buffer,
			flagTags: ''
		});
		if (first.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(first)}`);
		const repair = first.structure?.ihdrRepair;
		expect(repair?.recoveredHeight).toBe(HEIGHT);

		const patched = await send({
			kind: 'patchIhdr',
			id: 2,
			name: 'cut.png',
			width: repair!.recoveredWidth,
			height: repair!.recoveredHeight
		});
		if (patched.status !== 'patched') throw new Error(`patch failed: ${JSON.stringify(patched)}`);
		expect(new DataView(patched.bytes.buffer).getUint32(HEIGHT_OFFSET)).toBe(HEIGHT);

		const second = await send({
			kind: 'analyse',
			id: 3,
			name: 'cut.png',
			bytes: patched.bytes.slice().buffer,
			flagTags: ''
		});
		if (second.status !== 'ok') throw new Error(`reanalysis failed: ${JSON.stringify(second)}`);
		expect(second.structure?.chunks.every((chunk) => chunk.crcOk)).toBe(true);
		expect(second.structure?.ihdrRepair).toBeNull();
	});

	it('reads the pixels of a PNG too big for the budget a nested file gets', async () => {
		worker = new AnalysisWorker();
		const side = 1000;
		const png = encodePng(side, side, 2, new Uint8Array(side * side * 3).fill(90));

		const response = await send({
			kind: 'analyse',
			id: 1,
			name: 'big.png',
			bytes: png.slice().buffer,
			flagTags: ''
		});
		if (response.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(response)}`);

		expect(response.pixelError).toBeNull();
		expect(response.sweep).not.toBeNull();
	});

	it('reports a patch with no file loaded instead of analysing nothing', async () => {
		worker = new AnalysisWorker();

		const response = await send({ kind: 'patchIhdr', id: 1, name: 'x', width: 1, height: 1 });

		expect(response.status).toBe('error');
	});

	it('reads a flag out of a deleted database row, cell by cell', async () => {
		worker = new AnalysisWorker();
		const bytes = await (await fetch('/samples/databases/app.sqlite')).arrayBuffer();

		const response = await send({
			kind: 'analyse',
			id: 1,
			name: 'app.sqlite',
			bytes,
			flagTags: 'flag'
		});
		if (response.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(response)}`);

		expect(response.sqlite?.flags).toContainEqual({
			text: 'flag{deleted_rows_never_left}',
			table: 'members',
			deleted: true
		});
	});
});
