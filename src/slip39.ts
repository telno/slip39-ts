/* eslint-disable radix */
import * as slipHelper from './slip39_helper';
import { MIN_ENTROPY_BITS } from './constants';
import { bitsToBytes, generateArray } from './utils';
import * as allUtils from './utils'

const MAX_DEPTH = 2;

/**
  * Slip39Node
  * For root node, description refers to the whole set's title e.g. "Hardware wallet X SSSS shares"
  * For children nodes, description refers to the group e.g. "Family group: mom, dad, sister, wife"
  */
export class Slip39Node {
  public readonly index: number;
  public description: string;
  public mnemonic: string;
  public children: Slip39Node[];

  constructor(index = 0, description = '', mnemonic = '', children = []) {
    this.index = index;
    this.description = description;
    this.mnemonic = mnemonic;
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

export interface Slip39ConstructorOptions {
  iterationExponent: number;
  identifier: number[];
  groupCount: number;
  groupThreshold: number;
  encryptedMasterSecret: number[];
  groups: (number|string)[][];
  threshold: number;
  title: string;
}

function validateConstructorOptions(options: Slip39ConstructorOptions) {
  if (!options.identifier) {
    throw new Error('missing required parameter identifier');
  }

  if (!options.groupCount) {
    throw new Error('missing required parameter groupCount');
  }

  if (!options.groupThreshold) {
    throw new Error('missing required parameter groupThreshold');
  }
}

//
// The typescript implementation of the SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes
// see: https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
//
class Slip39 {
  public readonly iterationExponent: number;
  public readonly identifier: number[];
  public readonly groupCount: number;
  public readonly groupThreshold: number;

  protected _root: Slip39Node
  public get root() { return this._root }

  constructor(options: Slip39ConstructorOptions){
    validateConstructorOptions(options)
    this.iterationExponent = options.iterationExponent;
    this.identifier = options.identifier;
    this.groupCount = options.groupCount;
    this.groupThreshold = options.groupThreshold;
    this._root = new Slip39Node()
  }

  static async build(options: Slip39ConstructorOptions): Promise<Slip39> {
      const slip = new Slip39(options)
      slip._root = await slip.buildRecursive(new Slip39Node(), options.groups, options.encryptedMasterSecret, options.threshold)
      return slip
  }

  static async fromArray(
    masterSecret: number[],
    { passphrase = '', threshold = 1, groups = [[1, 1, 'Default 1-of-1 group share']], iterationExponent = 0, title = 'My default slip39 shares' } = {}
  ) {

    if (masterSecret.length * 8 < MIN_ENTROPY_BITS) {
      throw Error(
        `The length of the master secret (${masterSecret.length} bytes) must be at least ${bitsToBytes(
          MIN_ENTROPY_BITS
        )} bytes.`
      );
    }

    if (masterSecret.length % 2 !== 0) {
      throw Error('The length of the master secret in bytes must be an even number.');
    }

    if (!/^[\x20-\x7E]*$/.test(passphrase)) {
      throw Error('The passphrase must contain only printable ASCII characters (code points 32-126).');
    }

    if (threshold > groups.length) {
      throw Error(
        `The requested group threshold (${threshold}) must not exceed the number of groups (${groups.length}).`
      );
    }

    groups.forEach((item) => {
      if (item[0] === 1 && item[1] > 1) {
        throw Error(
          `Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. ${groups.join()}`
        );
      }
    });

    const identifier = slipHelper.generateIdentifier();
    const encryptedMasterSecret = await slipHelper.crypt(masterSecret, passphrase, iterationExponent, identifier);
    
    const result = await Slip39.build({
      iterationExponent: iterationExponent,
      identifier: identifier,
      groupCount: groups.length,
      groupThreshold: threshold,
      encryptedMasterSecret,
      groups,
      threshold,
      title: title
    });

    return result
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
    return splitted.map(pathFragment => {
      return parseInt(pathFragment);
    });
  }




  private async buildRecursive(
    currentNode: Slip39Node,
    nodes: (number|string)[][],
    secret: number[],
    threshold: number,
    index?: number
  ): Promise<Slip39Node> {

    if (nodes.length === 0) { // it's a leaf node
      if (index === undefined) {
        throw new Error('index must be defined for leaf nodes');
      }
      currentNode.mnemonic = slipHelper.encodeMnemonic(
        this.identifier,
        this.iterationExponent,
        index,
        this.groupThreshold,
        this.groupCount,
        currentNode.index,
        threshold,
        secret
      );
      return currentNode;
    }

    const secretShares = await slipHelper.splitSecret(threshold, nodes.length, secret);
    let children: Slip39Node[] = [];
    let initial: Promise<void>|undefined // using reduce as async replacement of foreach
    await nodes.reduce(async (prevOp, item, idx) => {
      await prevOp
      if (item.length < 2
          || typeof item[0] !== 'number' || typeof item[1] !== 'number') { 
            throw new Error('Group array must contain two numbers') 
      }

      // n=threshold
      const n = item[0];
      // m=members
      const m = item[1];
      // d=description
      const d: string = (item.length > 2 && typeof item[2] === 'string') ? item[2] : '';

      // Generate leaf members, means their `m` is `0`
      const members = generateArray([], m, () => [n, 0, d]) as number[][];
      const node = new Slip39Node(idx, d);
      const branch = await this.buildRecursive(node, members, secretShares[idx], n, currentNode.index);

      children = children.concat(branch);
      //idx = idx + 1;
      
    }, initial);

    currentNode.children = children;
    return currentNode;
  }
}

export const utils = allUtils
export const build = Slip39.build
export const fromArray = Slip39.fromArray
export const combineMnemonics = slipHelper.combineMnemonics
export const validateMnemonic = slipHelper.validateMnemonic