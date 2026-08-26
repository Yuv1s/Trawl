/** Uncompressed PCM: no encoder library needed, just the 44-byte header PCM
 *  players expect in front of the raw samples. */
export function encodeWavPcm16(
	sampleRate: number,
	channels: number,
	samples: Int16Array
): Uint8Array {
	const bitsPerSample = 16;
	const blockAlign = channels * (bitsPerSample / 8);
	const dataSize = samples.length * 2;
	const out = new Uint8Array(44 + dataSize);
	const view = new DataView(out.buffer);
	const ascii = (offset: number, text: string) => {
		for (let i = 0; i < text.length; i++) out[offset + i] = text.charCodeAt(i);
	};

	ascii(0, 'RIFF');
	view.setUint32(4, 36 + dataSize, true);
	ascii(8, 'WAVE');
	ascii(12, 'fmt ');
	view.setUint32(16, 16, true);
	view.setUint16(20, 1, true); // PCM
	view.setUint16(22, channels, true);
	view.setUint32(24, sampleRate, true);
	view.setUint32(28, sampleRate * blockAlign, true);
	view.setUint16(32, blockAlign, true);
	view.setUint16(34, bitsPerSample, true);
	ascii(36, 'data');
	view.setUint32(40, dataSize, true);

	for (let i = 0; i < samples.length; i++) view.setInt16(44 + i * 2, samples[i], true);
	return out;
}
