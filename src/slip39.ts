/* eslint-disable radix */
import * as slipHelper from './slip39_helper';
import { generateArray } from './slip39_helper';

const MAX_DEPTH = 2;

//
// Slip39Node
//
class Slip39Node {
  public mnemonic: string;
  public readonly index: number;
  public children: Slip39Node[];

  constructor(index = 0, mnemonic = '', children = []) {
    this.mnemonic = mnemonic;
    this.index = index;
    this.children = children;
  }

  get mnemonics(): string[] {
    if (this.children.length === 0) {
      return [this.mnemonic];
    }
    return this.children.reduce((prev: string[], item) => {
      return prev.concat(item.mnemonics);
    }, []);
  }
}

interface Slip39ConstructorOptions {
  iterationExponent: number;
  identifier: number[];
  groupCount: number;
  groupThreshold: number;
  ems: number[];
  groups: number[][];
  threshold: number;
}

//
// The javascript implementation of the SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes
// see: https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
//
export class Slip39 {
  public readonly root: Slip39Node;
  public readonly iterationExponent: number;
  public readonly identifier: number[];
  public readonly groupCount: number;
  public readonly groupThreshold: number;

  constructor({
    iterationExponent = 0,
    identifier,
    groupCount,
    groupThreshold,
    ems,
    groups,
    threshold,
  }: Slip39ConstructorOptions) {
    this.iterationExponent = iterationExponent;

    if (!identifier) {
      throw new Error('missing required parameter identifier');
    }
    this.identifier = identifier;

    if (!groupCount) {
      throw new Error('missing required parameter groupCount');
    }
    this.groupCount = groupCount;

    if (!groupThreshold) {
      throw new Error('missing required parameter groupThreshold');
    }
    this.groupThreshold = groupThreshold;
    this.root = this.buildRecursive(
      new Slip39Node(),
      groups,
      ems,
      threshold
    );
  }

  static fromArray(masterSecret: number[], {
    passphrase = '',
    threshold = 1,
    groups = [
      [1, 1]
    ],
    iterationExponent = 0
  } = {}) {
    if (masterSecret.length * 8 < slipHelper.MIN_ENTROPY_BITS) {
      throw Error(`The length of the master secret (${masterSecret.length} bytes) must be at least ${slipHelper.bitsToBytes(slipHelper.MIN_ENTROPY_BITS)} bytes.`);
    }

    if (masterSecret.length % 2 !== 0) {
      throw Error('The length of the master secret in bytes must be an even number.');
    }

    if (!/^[\x20-\x7E]*$/.test(passphrase)) {
      throw Error('The passphrase must contain only printable ASCII characters (code points 32-126).');
    }

    if (threshold > groups.length) {
      throw Error(`The requested group threshold (${threshold}) must not exceed the number of groups (${groups.length}).`);
    }

    groups.forEach((item) => {
      if (item[0] === 1 && item[1] > 1) {
        throw Error(`Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. ${groups.join()}`);
      }
    });

    const identifier = slipHelper.generateIdentifier();
    const ems = slipHelper.crypt(masterSecret, passphrase, iterationExponent, identifier);

    const slip = new Slip39({
      iterationExponent: iterationExponent,
      identifier: identifier,
      groupCount: groups.length,
      groupThreshold: threshold,
      ems,
      groups,
      threshold,
    });

    return slip;
  }

  buildRecursive(current: Slip39Node, nodes: number[][], secret: number[], threshold: number, index?: number): Slip39Node {
    // It means it's a leaf.
    if (nodes.length === 0) {
      if (index === undefined) {
        throw new Error('index must be defined for leaf nodes');
      }
      current.mnemonic = slipHelper.encodeMnemonic(
        this.identifier,
        this.iterationExponent,
        index,
        this.groupThreshold,
        this.groupCount,
        current.index,
        threshold,
        secret
      );
      return current;
    }

    const secretShares = slipHelper.splitSecret(threshold, nodes.length, secret);
    let children: Slip39Node[] = [];
    let idx = 0;

    nodes.forEach((item) => {
      // n=threshold
      const n = item[0];
      // m=members
      const m = item[1];

      // Generate leaf members, means their `m` is `0`
      const members = generateArray([], m, () => [n, 0]) as number[][];

      const node = new Slip39Node(idx);
      const branch = this.buildRecursive(node, members, secretShares[idx], n, current.index);

      children = children.concat(branch);
      idx = idx + 1;
    });
    current.children = children;
    return current;
  }

  static recoverSecret(mnemonics: string[], passphrase: string) {
    return slipHelper.combineMnemonics(mnemonics, passphrase);
  }

  static validateMnemonic(mnemonic: string) {
    return slipHelper.validateMnemonic(mnemonic);
  }

  fromPath(path: string) {
    this.validatePath(path);

    const children = this.parseChildren(path);

    if (typeof children === 'undefined' || children.length === 0) {
      return this.root;
    }

    return children.reduce((prev, childNumber) => {
      const childrenLen = prev.children.length;
      if (childNumber >= childrenLen) {
        throw new Error(`The path index (${childNumber}) exceeds the children index (${childrenLen - 1}).`);
      }

      return prev.children[childNumber];
    }, this.root);
  }

  validatePath(path: string) {
    if (!path.match(/(^r)(\/\d{1,2}){0,2}$/)) {
      throw new Error('Expected valid path e.g. "r/0/0".');
    }

    const depth = path.split('/');
    const pathLength = depth.length - 1;
    if (pathLength > MAX_DEPTH) {
      throw new Error(`Path's (${path}) max depth (${MAX_DEPTH}) is exceeded (${pathLength}).`);
    }
  }

  parseChildren(path: string) {
    const splitted = path.split('/').slice(1);
    return splitted.map((pathFragment) => {
      return parseInt(pathFragment);
    });
  }
}
