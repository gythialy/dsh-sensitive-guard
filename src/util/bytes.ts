/** UTF-8 byte length without allocating a Buffer for short strings. */
export function utf8ByteLength(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}
