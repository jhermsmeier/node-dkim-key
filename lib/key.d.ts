interface KeyOptions {
  version: string;
  type: string;
  flags: string;
  granularity: string;
  hash: string;
  notes: string;
  service: string;
  key: string;
}

declare class Key {

  version: string;
  type: string;
  flags: string;
  granularity: string;
  hash: string;
  notes: string;
  service: string;
  key: string;

  constructor(options: Partial<KeyOptions>);

  static create(options: KeyOptions): Key;
  static parse(value: string): Key;

  static fieldMap: {
    g: string;
    h: string;
    k: string;
    n: string;
    p: string;
    s: string;
    t: string;
    v: string;
  };

  static keys: string[];

  parse(input: string): Key;

  toString(): string;

}

export = Key;