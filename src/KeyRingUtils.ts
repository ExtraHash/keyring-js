import {
  decodeBase64,
  decodeUTF8,
  encodeBase64,
  encodeUTF8,
} from "tweetnacl-util";

/**
 * The Utils class provides a few helpful type conversion functions for
 * working with ed25519 keys and signatures.
 *
 * Note that the methods are static so you do not need to initialize the class.
 */

export class KeyRingUtils {
  /**
   * Encodes a Uint8Array to a utf8 string.
   *
   * @returns The utf8 string.
   */
  public static encodeUTF8 = encodeUTF8;
  /**
   * Decodes a utf8 string into a Uint8Array.
   *
   * @returns The Uint8Array.
   */
  public static decodeUTF8 = decodeUTF8;
  /**
   * Encodes a Uint8Array to a base64 string.
   *
   * @returns The base64 string.
   */
  public static encodeBase64 = encodeBase64;
  /**
   * Decodes a base64 string into a Uint8Array.
   *
   * @returns The Uint8Array.
   */
  public static decodeBase64 = decodeBase64;

  /**
   * Decodes a hex string into a Uint8Array.
   *
   * @returns The Uint8Array.
   */
  public static decodeHex(hexString: string): Uint8Array {
    return new Uint8Array(
      hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
    );
  }

  /**
   * Encodes a Uint8Array to a hex string.
   *
   * @returns The hex string.
   */
  public static encodeHex(bytes: Uint8Array): string {
    return bytes.reduce(
      (str, byte) => str + byte.toString(16).padStart(2, "0"),
      ""
    );
  }

  /**
   * @ignore
   */
  public static sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
