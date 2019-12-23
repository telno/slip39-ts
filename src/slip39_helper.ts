import * as crypto from 'crypto';

import { EXP_TABLE, LOG_TABLE } from './tables';
import { WORD_LIST } from './words';

// The length of the radix in bits.
const RADIX_BITS = 10;

// The length of the random identifier in bits.
const ID_BITS_LENGTH = 15;

// The length of the iteration exponent in bits.
const ITERATION_EXP_BITS_LENGTH = 5;

// The length of the random identifier and iteration exponent in words.
const ITERATION_EXP_WORDS_LENGTH = Math.trunc((ID_BITS_LENGTH + ITERATION_EXP_BITS_LENGTH + RADIX_BITS - 1) / RADIX_BITS);

// The maximum iteration exponent
const MAX_ITERATION_EXP = Math.pow(2, ITERATION_EXP_BITS_LENGTH);

// The maximum number of shares that can be created.
const MAX_SHARE_COUNT = 16;

// The length of the RS1024 checksum in words.
const CHECKSUM_WORDS_LENGTH = 3;

// The length of the digest of the shared secret in bytes.
const DIGEST_LENGTH = 4;

// The customization string used in the RS1024 checksum and in the PBKDF2 salt.
const SALT_STRING = 'shamir';

// The minimum allowed entropy of the master secret.
export const MIN_ENTROPY_BITS = 128;

// The minimum allowed length of the mnemonic in words.
const METADATA_WORDS_LENGTH = ITERATION_EXP_WORDS_LENGTH + 2 + CHECKSUM_WORDS_LENGTH;

// The length of the mnemonic in words without the share value.
const MNEMONICS_WORDS_LENGTH = Math.trunc( METADATA_WORDS_LENGTH + (MIN_ENTROPY_BITS + RADIX_BITS - 1) / RADIX_BITS);

// The minimum number of iterations to use in PBKDF2.
const ITERATION_COUNT = 10000;

// The number of rounds to use in the Feistel cipher.
const ROUND_COUNT = 4;

// The index of the share containing the digest of the shared secret.
const DIGEST_INDEX = 254;

// The index of the share containing the shared secret.
const SECRET_INDEX = 255;

export const WORD_LIST_MAP  = WORD_LIST.reduce((obj: { [word: string]: number }, val, idx) => {
  obj[val] = idx;
  return obj;
}, {});

function listsAreEqual(a: null | unknown[], b: null | unknown[]) {
  if (a === null || b === null || a.length !== b.length) {
    return false;
  }

  let i = 0;
  return a.every((item) => {
    return b[i++] === item;
  });
}


function generateArray<T>(arr: (T | number)[], n: number, v?: (idx: number) => T) {
  const m = n || arr.length;
  for (let i = 0; i < m; i++) {
    arr.push(typeof v === 'undefined' ? i : v(i));
  }
  return arr;
}

function encodeHexString(s: string): number[] {
  const bytes = [];
  for (let i = 0; i < s.length; ++i) {
    bytes.push(s.charCodeAt(i));
  }
  return bytes;
}

/*
//
// Helper functions for SLIP39 implementation.
//
Array.prototype.decodeHex = function () {
  let str = [];
  const hex = this.toString().split(',');
  for (let i = 0; i < hex.length; i++) {
    str.push(String.fromCharCode(hex[i]));
  }
  return str.toString().replace(/,/g, '');
};

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

const BIGINT_WORD_BITS = BigInt(8);

function decodeBigInt(bytes: number[]): bigint {
  let result = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    const b = BigInt(bytes[bytes.length - i - 1]);
    result = result + (b << BIGINT_WORD_BITS * BigInt(i));
  }
  return result;
}

function encodeBigInt(number: bigint, paddedLength = 0): number[] {
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

function bitsToWords(n: number) {
  const res = (n + RADIX_BITS - 1) / RADIX_BITS;
  return Math.trunc(res);
}

function randomBytes(length = 32): number[] {
  const randoms = crypto.randomBytes(length);
  return Array.prototype.slice.call(randoms, 0);
}

//
// The round function used internally by the Feistel cipher.
//
function roundFunction(round: number, passphrase: number[], exp: number, salt: number[], secret: number[]) {
  const saltedSecret = salt.concat(secret);
  const roundedPhrase = [round].concat(passphrase);
  const count = (ITERATION_COUNT << exp) / ROUND_COUNT;

  const key = crypto.pbkdf2Sync(Buffer.from(roundedPhrase), Buffer.from(saltedSecret), count, secret.length, 'sha256');
  return Array.prototype.slice.call(key, 0);
}

function getSalt(identifier: number[]) {
  const salt = encodeHexString(SALT_STRING);
  return salt.concat(identifier);
}
function xor(a: number[], b: number[]) {
  if (a.length !== b.length) {
    throw new Error(`Invalid padding in mnemonic or insufficient length of mnemonics (${a.length} or ${b.length})`);
  }
  return generateArray([], a.length, (i) => a[i] ^ b[i]);
}

export function crypt(masterSecret: number[], passphrase: string, iterationExponent: number, identifier: number[], encrypt = true) {
  // Iteration exponent validated here.
  if (iterationExponent < 0 || iterationExponent > MAX_ITERATION_EXP) {
    throw Error(`Invalid iteration exponent (${iterationExponent}). Expected between 0 and ${MAX_ITERATION_EXP}`);
  }

  let IL = masterSecret.slice().slice(0, masterSecret.length / 2);
  let IR = masterSecret.slice().slice(masterSecret.length / 2);

  const pwd = encodeHexString(passphrase);

  const salt = getSalt(identifier);

  let range = generateArray([], ROUND_COUNT);
  range = encrypt ? range : range.reverse();

  range.forEach((round: number) => {
    const f = roundFunction(round, pwd, iterationExponent, salt, IR);
    const t = xor(IL, f);
    IL = IR;
    IR = t;
  });
  return IR.concat(IL);
}

function createDigest(randomData: number[], sharedSecret: number[]): number[] {
  const hmac = crypto.createHmac('sha256', Buffer.from(randomData));

  hmac.update(Buffer.from(sharedSecret));

  let result = hmac.digest();
  result = result.slice(0, 4);
  return Array.prototype.slice.call(result, 0);
}

function interpolate(shares: Map<number, number[]>, x: number): number[] {
  const arr = Array.from(shares.values());
  const sharesValueLengths = new Set(arr);

  if (sharesValueLengths.size !== 1) {
    throw new Error('Invalid set of shares. All share values must have the same length.');
  }

  const existing = shares.get(x);
  if (existing) {
    return existing;
  }

  // Logarithm of the product of (x_i - x) for i = 1, ... , k.
  let logProd = 0;

  shares.forEach((v, k) => {
    logProd = logProd + LOG_TABLE[k ^ x];
  });

  const results = generateArray([], sharesValueLengths.values().next().value, () => 0);

  shares.forEach((v, k) => {
    // The logarithm of the Lagrange basis polynomial evaluated at x.
    let sum = 0;
    shares.forEach((vv, kk) => {
      sum = sum + LOG_TABLE[k ^ kk];
    });

    // FIXME: -18 % 255 = 237. IT shoulud be 237 and not -18 as it's
    // implemented in javascript.
    const basis = (logProd - LOG_TABLE[k ^ x] - sum) % 255;

    const logBasisEval = basis < 0 ? 255 + basis : basis;

    v.forEach((item: number, idx: number) => {
      const shareVal = item;
      const intermediateSum = results[idx];
      const r = shareVal !== 0 ? EXP_TABLE[(LOG_TABLE[shareVal] + logBasisEval) % 255] : 0;

      results[idx] = intermediateSum ^ r;
    });
  });
  return results;
}

export function splitSecret(threshold: number, shareCount: number, sharedSecret: number[]): number[][] {
  if (threshold <= 0) {
    throw Error(`The requested threshold (${threshold}) must be a positive integer.`);
  }

  if (threshold > shareCount) {
    throw Error(`The requested threshold (${threshold}) must not exceed the number of shares (${shareCount}).`);
  }

  if (shareCount > MAX_SHARE_COUNT) {
    throw Error(`The requested number of shares (${shareCount}) must not exceed ${MAX_SHARE_COUNT}.`);
  }
  //  If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return generateArray([], shareCount, () => sharedSecret) as number[][];
  }

  const randomShareCount = threshold - 2;

  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH);
  const digest = createDigest(randomPart, sharedSecret);

  const baseShares = new Map<number, number[]>();
  let shares: number[][] = [];
  if (randomShareCount) {
    shares = generateArray([], randomShareCount, () => randomBytes(sharedSecret.length)) as number[][];
    shares.forEach((item, idx) => {
      baseShares.set(idx, item);
    });
  }
  baseShares.set(DIGEST_INDEX, digest.concat(randomPart));
  baseShares.set(SECRET_INDEX, sharedSecret);

  for (let i = randomShareCount; i < shareCount; i++) {
    const rr = interpolate(baseShares, i);
    shares.push(rr);
  }

  return shares;
}

//
// Returns a randomly generated integer in the range 0, ... , 2**ID_BITS_LENGTH - 1.
//
export function generateIdentifier() {
  const byte = bitsToBytes(ID_BITS_LENGTH);
  const bits = ID_BITS_LENGTH % 8;
  const identifier = randomBytes(byte);

  identifier[0] = identifier[0] & (1 << bits) - 1;

  return identifier;
}


function rs1024Polymod(data: number[]) {
  const GEN = [
    0xE0E040,
    0x1C1C080,
    0x3838100,
    0x7070200,
    0xE0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x3F3F120
  ];
  let chk = 1;

  data.forEach((byte) => {
    const b = chk >> 20;
    chk = (chk & 0xFFFFF) << 10 ^ byte;

    for (let i = 0; i < 10; i++) {
      const gen = (b >> i & 1) !== 0 ? GEN[i] : 0;
      chk = chk ^ gen;
    }
  });

  return chk;
}

function rs1024CreateChecksum(data: number[]) {
  const values = encodeHexString(SALT_STRING)
    .concat(data)
    .concat(generateArray([], CHECKSUM_WORDS_LENGTH, () => 0));
  const polymod = rs1024Polymod(values) ^ 1;
  return generateArray([], CHECKSUM_WORDS_LENGTH, (i) => polymod >> 10 * i & 1023).reverse();
}

function rs1024VerifyChecksum(data: number[]) {
  return rs1024Polymod(encodeHexString(SALT_STRING).concat(data)) === 1;
}

//
// Converts a list of base 1024 indices in big endian order to an integer value.
//
function intFromIndices(indices: number[]) {
  let value = BigInt(0);
  const radix = BigInt(Math.pow(2, RADIX_BITS));
  indices.forEach((index) => {
    value = value * radix + BigInt(index);
  });

  return value;
}

//
// Converts a Big integer value to indices in big endian order.
//
function intToIndices(value: bigint, length: number, bits: number) {
  const mask = BigInt((1 << bits) - 1);
  const result = generateArray([], length, (i) => Number(value >> BigInt(i) * BigInt(bits) & mask));
  return result.reverse();
}

function mnemonicFromIndices(indices: number[]) {
  const result = indices.map((index) => {
    return WORD_LIST[index];
  });
  return result.toString().split(',').join(' ');
}

function mnemonicToIndices(mnemonic: string) {
  const words = mnemonic.toLowerCase().split(' ');
  return words.reduce((prev: number[], item) => {
    const index = WORD_LIST_MAP[item];
    if (typeof index === 'undefined') {
      throw new Error(`Invalid mnemonic word ${item}.`);
    }
    return prev.concat(index);
  }, []);
}

function recoverSecret(threshold: number, shares: Map<number, number[]>): number[] {
  // If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return shares.values().next().value;
  }

  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH);
  const randomPart = digestShare.slice(DIGEST_LENGTH);

  const recoveredDigest = createDigest(randomPart, sharedSecret);
  if (!listsAreEqual(digest, recoveredDigest)) {
    throw new Error('Invalid digest of the shared secret.');
  }
  return sharedSecret;
}


interface DecodedMnemonic {
  identifier: number;
  iterationExponent: number;
  groupIndex: number;
  groupThreshold: number;
  groupCount: number;
  memberIndex: number;
  memberThreshold: number;
  share: number[];
}

//
// Converts a share mnemonic to share data.
//
function decodeMnemonic(mnemonic: string): DecodedMnemonic {
  const data = mnemonicToIndices(mnemonic);

  if (data.length < MNEMONICS_WORDS_LENGTH) {
    throw new Error(`Invalid mnemonic length. The length of each mnemonic must be at least ${MNEMONICS_WORDS_LENGTH} words.`);
  }

  const paddingLen = RADIX_BITS * (data.length - METADATA_WORDS_LENGTH) % 16;
  if (paddingLen > 8) {
    throw new Error('Invalid mnemonic length.');
  }

  if (!rs1024VerifyChecksum(data)) {
    throw new Error('Invalid mnemonic checksum');
  }

  const idExpInt = Number(intFromIndices(data.slice(0, ITERATION_EXP_WORDS_LENGTH)));
  const identifier = idExpInt >> ITERATION_EXP_BITS_LENGTH;
  const iterationExponent = idExpInt & (1 << ITERATION_EXP_BITS_LENGTH) - 1;
  const tmp = intFromIndices(data.slice(ITERATION_EXP_WORDS_LENGTH, ITERATION_EXP_WORDS_LENGTH + 2));

  const indices = intToIndices(tmp, 5, 4);

  const groupIndex = indices[0];
  const groupThreshold = indices[1];
  const groupCount = indices[2];
  const memberIndex = indices[3];
  const memberThreshold = indices[4];

  const valueData = data.slice(ITERATION_EXP_WORDS_LENGTH + 2, data.length - CHECKSUM_WORDS_LENGTH);

  if (groupCount < groupThreshold) {
    throw new Error(`Invalid mnemonic: ${mnemonic}.\n Group threshold (${groupThreshold}) cannot be greater than group count (${groupCount}).`);
  }

  const valueInt = intFromIndices(valueData);

  try {
    const valueByteCount = bitsToBytes(RADIX_BITS * valueData.length - paddingLen);
    const share = encodeBigInt(valueInt, valueByteCount);

    return {
      identifier: identifier,
      iterationExponent: iterationExponent,
      groupIndex: groupIndex,
      groupThreshold: groupThreshold + 1,
      groupCount: groupCount + 1,
      memberIndex: memberIndex,
      memberThreshold: memberThreshold + 1,
      share: share
    };
  } catch (e) {
    throw new Error(`Invalid mnemonic padding (${e})`);
  }
}

interface DecodedMnemonics {
  identifier: number;
  iterationExponent: number;
  groupThreshold: number;
  groupCount: number;
  groups: Map<number, Map<number, Map<number, number[]>>>;
}

function decodeMnemonics(mnemonics: string[]): DecodedMnemonics {
  const identifiers = new Set<number>();
  const iterationExponents = new Set<number>();
  const groupThresholds = new Set<number>();
  const groupCounts = new Set<number>();
  const groups: DecodedMnemonics['groups'] = new Map();

  mnemonics.forEach((mnemonic) => {
    const decoded = decodeMnemonic(mnemonic);

    identifiers.add(decoded.identifier);
    iterationExponents.add(decoded.iterationExponent);
    const groupIndex = decoded.groupIndex;
    groupThresholds.add(decoded.groupThreshold);
    groupCounts.add(decoded.groupCount);
    const memberIndex = decoded.memberIndex;
    const memberThreshold = decoded.memberThreshold;
    const share = decoded.share;

    const group = !groups.has(groupIndex) ? new Map<number, Map<number, number[]>>() : groups.get(groupIndex);
    if (!group) {
      throw new Error('unable to initalize group map');
    }

    const member = !group.has(memberThreshold) ? new Map<number, number[]>() : group.get(memberThreshold);
    if (!member) {
      throw new Error('unable to initalize member map');
    }

    member.set(memberIndex, share);
    group.set(memberThreshold, member);
    if (group.size !== 1) {
      throw new Error('Invalid set of mnemonics. All mnemonics in a group must have the same member threshold.');
    }
    groups.set(groupIndex, group);
  });

  if (identifiers.size !== 1 || iterationExponents.size !== 1) {
    throw new Error(`Invalid set of mnemonics. All mnemonics must begin with the same ${ITERATION_EXP_WORDS_LENGTH} words.`);
  }

  if (groupThresholds.size !== 1) {
    throw new Error('Invalid set of mnemonics. All mnemonics must have the same group threshold.');
  }

  if (groupCounts.size !== 1) {
    throw new Error('Invalid set of mnemonics. All mnemonics must have the same group count.');
  }

  return {
    identifier: identifiers.values().next().value,
    iterationExponent: iterationExponents.values().next().value,
    groupThreshold: groupThresholds.values().next().value,
    groupCount: groupCounts.values().next().value,
    groups: groups
  };
}

function groupPrefix(identifier: number, iterationExponent: number, groupIndex: number, groupThreshold: number, groupCount: number) {
  const idExpInt = BigInt((identifier << ITERATION_EXP_BITS_LENGTH) + iterationExponent);
  const indc = intToIndices(idExpInt, ITERATION_EXP_WORDS_LENGTH, RADIX_BITS);
  const indc2 = (groupIndex << 6) + (groupThreshold - 1 << 2) + (groupCount - 1 >> 2);
  indc.push(indc2);

  return indc;
}


//
// Combines mnemonic shares to obtain the master secret which was previously
// split using Shamir's secret sharing scheme.
//
export function combineMnemonics(mnemonics: string[], passphrase = '') {
  if (mnemonics === null || mnemonics.length === 0) {
    throw new Error('The list of mnemonics is empty.');
  }

  const decoded = decodeMnemonics(mnemonics);
  const identifier = decoded.identifier;
  const iterationExponent = decoded.iterationExponent;
  const groupThreshold = decoded.groupThreshold;
  const groupCount = decoded.groupCount;
  const groups = decoded.groups;

  if (groups.size < groupThreshold) {
    throw new Error(`Insufficient number of mnemonic groups (${groups.size}). The required number of groups is ${groupThreshold}.`);
  }

  if (groups.size !== groupThreshold) {
    throw new Error(`Wrong number of mnemonic groups. Expected $groupThreshold groups, but ${groups.size} were provided.`);
  }

  const allShares = new Map<number, number[]>();
  groups.forEach((members: Map<number, Map<number, number[]>>, groupIndex: number) => {
    const threshold = members.keys().next().value;
    const shares = members.values().next().value;
    if (shares.size !== threshold) {
      const prefix = groupPrefix(
        identifier,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount
      );
      throw new Error(`Wrong number of mnemonics. Expected ${threshold} mnemonics starting with "${mnemonicFromIndices(prefix)}", \n but ${shares.size} were provided.`);
    }

    const recovered = recoverSecret(threshold, shares);
    allShares.set(groupIndex, recovered);
  });

  const ems = recoverSecret(groupThreshold, allShares);
  const id = intToIndices(BigInt(identifier), ITERATION_EXP_WORDS_LENGTH, 8);
  return crypt(ems, passphrase, iterationExponent, id, false);
}

export function validateMnemonic(mnemonic: string) {
  try {
    decodeMnemonic(mnemonic);
    return true;
  } catch (error) {
    return false;
  }
}

//
//  Converts share data to a share mnemonic.
//
export function encodeMnemonic(
  identifier: number[],
  iterationExponent: number,
  groupIndex: number,
  groupThreshold: number,
  groupCount: number,
  memberIndex: number,
  memberThreshold: number,
  value: number[],
) {
  // Convert the share value from bytes to wordlist indices.
  const valueWordCount = bitsToWords(value.length * 8);

  const valueInt = decodeBigInt(value);
  const newIdentifier = Number(decodeBigInt(identifier));

  const gp = groupPrefix(newIdentifier, iterationExponent, groupIndex, groupThreshold, groupCount);
  const tp = intToIndices(valueInt, valueWordCount, RADIX_BITS);

  const calc = ((groupCount - 1 & 3) << 8) +
    (memberIndex << 4) +
    (memberThreshold - 1);

  gp.push(calc);
  const shareData = gp.concat(tp);

  const checksum = rs1024CreateChecksum(shareData);

  return mnemonicFromIndices(shareData.concat(checksum));
}
