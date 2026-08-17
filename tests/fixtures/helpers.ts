// Fixture helpers: the gzip/zip fixtures are generated from the .xml files at test time
// so there are no unregenerable binaries in the repo.
import { BlobWriter, configure, TextReader, Uint8ArrayReader, ZipWriter } from "@zip-js/zip-js";

configure({ useWebWorkers: false });

const DIR = new URL(".", import.meta.url);

export function fixtureText(name: string): string {
  return Deno.readTextFileSync(new URL(name, DIR));
}

export function fixtureBytes(name: string): Uint8Array {
  return new TextEncoder().encode(fixtureText(name));
}

export async function gzip(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function zip(members: Array<[string, string]>): Promise<Uint8Array> {
  const writer = new ZipWriter(new BlobWriter("application/zip"));
  for (const [name, content] of members) {
    await writer.add(name, new TextReader(content));
  }
  const blob = await writer.close();
  return new Uint8Array(await blob.arrayBuffer());
}

/** Same as `zip` but for members that are already binary (e.g. a nested .gz). */
export async function zipRaw(members: Array<[string, Uint8Array]>): Promise<Uint8Array> {
  const writer = new ZipWriter(new BlobWriter("application/zip"));
  for (const [name, content] of members) {
    await writer.add(name, new Uint8ArrayReader(content));
  }
  const blob = await writer.close();
  return new Uint8Array(await blob.arrayBuffer());
}

/** Base64 wrapped at `width` columns with CRLF, the way a real MUA emits an attachment. */
export function base64Lines(bytes: Uint8Array, width = 76): string {
  let binary = "";
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  const encoded = btoa(binary);
  const lines: string[] = [];
  for (let i = 0; i < encoded.length; i += width) lines.push(encoded.slice(i, i + width));
  return lines.join("\r\n");
}

/**
 * Turn a message written with plain newlines into wire-format bytes. Real mail uses CRLF, and
 * the MIME reader has to cope with both, so tests can pick either ending explicitly.
 */
export function messageBytes(text: string, ending: "\r\n" | "\n" = "\r\n"): Uint8Array {
  const normalized = text.replace(/\r\n/g, "\n");
  return new TextEncoder().encode(
    ending === "\n" ? normalized : normalized.replace(/\n/g, "\r\n"),
  );
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

/**
 * A gzip stream of `size` zero bytes — a decompression bomb. Built by streaming 1 MiB at a
 * time so the test itself never holds the uncompressed payload in memory.
 */
export async function gzipZeros(size: number): Promise<Uint8Array> {
  const CHUNK = 1024 * 1024;
  let remaining = size;
  const zeros = new ReadableStream<BufferSource>({
    pull(controller) {
      if (remaining <= 0) return controller.close();
      const n = Math.min(CHUNK, remaining);
      remaining -= n;
      controller.enqueue(new Uint8Array(n));
    },
  });
  const out = zeros.pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(out).arrayBuffer());
}
