// The length of the radix in bits.
import { WORD_LIST } from './words';

export const RADIX_BITS = 10;

// The length of the random identifier in bits.
export const ID_BITS_LENGTH = 15;

// The length of the iteration exponent in bits.
export const ITERATION_EXP_BITS_LENGTH = 5;

// The length of the random identifier and iteration exponent in words.
export const ITERATION_EXP_WORDS_LENGTH = Math.trunc((ID_BITS_LENGTH + ITERATION_EXP_BITS_LENGTH + RADIX_BITS - 1) / RADIX_BITS);

// The maximum iteration exponent
export const MAX_ITERATION_EXP = Math.pow(2, ITERATION_EXP_BITS_LENGTH);

// The maximum number of shares that can be created.
export const MAX_SHARE_COUNT = 16;

// The length of the RS1024 checksum in words.
export const CHECKSUM_WORDS_LENGTH = 3;

// The length of the digest of the shared secret in bytes.
export const DIGEST_LENGTH = 4;

// The customization string used in the RS1024 checksum and in the PBKDF2 salt.
export const SALT_STRING = 'shamir';

// The minimum allowed entropy of the master secret.
export const MIN_ENTROPY_BITS = 128;

// The minimum allowed length of the mnemonic in words.
export const METADATA_WORDS_LENGTH = ITERATION_EXP_WORDS_LENGTH + 2 + CHECKSUM_WORDS_LENGTH;

// The length of the mnemonic in words without the share value.
export const MNEMONICS_WORDS_LENGTH = Math.trunc( METADATA_WORDS_LENGTH + (MIN_ENTROPY_BITS + RADIX_BITS - 1) / RADIX_BITS);

// The minimum number of iterations to use in PBKDF2.
export const ITERATION_COUNT = 10000;

// The number of rounds to use in the Feistel cipher.
export const ROUND_COUNT = 4;

// The index of the share containing the digest of the shared secret.
export const DIGEST_INDEX = 254;

// The index of the share containing the shared secret.
export const SECRET_INDEX = 255;

export const WORD_LIST_MAP  = WORD_LIST.reduce((obj: { [word: string]: number }, val, idx) => {
  obj[val] = idx;
  return obj;
}, {});

export const BIGINT_WORD_BITS = BigInt(8);

