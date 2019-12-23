import * as crypto from "crypto";
import { BIGINT_WORD_BITS, RADIX_BITS } from './constants';

export function listsAreEqual(a: null | unknown[], b: null | unknown[]) {
  if (a === null || b === null || a.length !== b.length) {
    return false;
  }

  let i = 0;
  return a.every((item) => {
    return b[i++] === item;
  });
}


export function generateArray<T>(arr: (T | number)[], n: number, v?: (idx: number) => T) {
  const m = n || arr.length;
  for (let i = 0; i < m; i++) {
    arr.push(typeof v === 'undefined' ? i : v(i));
  }
  return arr;
}

export function encodeHexString(s: string): number[] {
  const bytes = [];
  for (let i = 0; i < s.length; ++i) {
    bytes.push(s.charCodeAt(i));
  }
  return bytes;
}
export function decodeHexString(s: number[]): string {
  const str: string[] = [];
  const hex = s.toString().split(',');
  for (let i = 0; i < hex.length; i++) {
    str.push(String.fromCharCode(Number(hex[i])));
  }
  return str.toString().replace(/,/g, '');
};

/*
Array.prototype.toHexString = function () {
  return Array.prototype.map.call(this, function (byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
};

Array.prototype.toByteArray = function (hexString) {
  for (let i = 0; i < hexString.length; i = i + 2) {
    this.push(parseInt(hexString.substr(i, 2), 16));
  }
  return this;
};
 */

export function decodeBigInt(bytes: number[]): bigint {
  let result = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    const b = BigInt(bytes[bytes.length - i - 1]);
    result = result + (b << BIGINT_WORD_BITS * BigInt(i));
  }
  return result;
}

export function encodeBigInt(number: bigint, paddedLength = 0): number[] {
  let num = number;
  const BYTE_MASK = BigInt(0xff);
  const BIGINT_ZERO = BigInt(0);
  const result = new Array(0);

  while (num > BIGINT_ZERO) {
    result.unshift(num & BYTE_MASK);
    num = num >> BIGINT_WORD_BITS;
  }

  // Zero padding to the length
  for (let i = result.length; i < paddedLength; i++) {
    result.unshift(0);
  }

  if (paddedLength !== 0 && result.length > paddedLength) {
    throw new Error(`Error in encoding BigInt value, expected less than ${paddedLength} length value, got ${result.length}`);
  }

  return result;
}

export function bitsToBytes(n: number) {
  const res = (n + 7) / 8;
  return Math.trunc(res);
}

export function bitsToWords(n: number) {
  const res = (n + RADIX_BITS - 1) / RADIX_BITS;
  return Math.trunc(res);
}

export function randomBytes(length = 32): number[] {
  const randoms = crypto.randomBytes(length);
  return Array.prototype.slice.call(randoms, 0);
}
