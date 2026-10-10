export class ContractError extends TypeError {
  readonly code = 'invalid-contract';
  readonly field: string;

  constructor(field: string, expectation: string) {
    super(`${field}: ${expectation}`);
    this.name = 'ContractError';
    this.field = field;
  }
}

export function record(
  value: unknown,
  field: string,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ContractError(field, 'expected an object');
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ContractError(field, 'expected a plain data object');
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !keys.includes(key)) {
      throw new ContractError(field, 'unrecognized field');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new ContractError(field, 'accessors are not data fields');
    }
  }
  return value as Record<string, unknown>;
}

export function text(value: unknown, field: string, maxLength = 4096): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxLength ||
    value.trim().length === 0 ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    throw new ContractError(field, `expected nonempty text of at most ${maxLength} characters`);
  }
  return value;
}

export function oneOf<const T extends readonly string[]>(
  value: unknown,
  values: T,
  field: string,
): T[number] {
  if (typeof value !== 'string' || !values.includes(value)) {
    throw new ContractError(field, `expected one of ${values.join(', ')}`);
  }
  return value as T[number];
}

export function integer(
  value: unknown,
  field: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new ContractError(field, `expected an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

export function array<T>(
  value: unknown,
  field: string,
  parse: (entry: unknown) => T,
  minimum = 0,
): readonly T[] {
  if (!Array.isArray(value) || value.length < minimum) {
    throw new ContractError(field, `expected an array with at least ${minimum} entries`);
  }
  const entries: T[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      throw new ContractError(field, 'sparse arrays are not supported');
    }
    entries.push(parse(value[index]));
  }
  return Object.freeze(entries);
}

export function unique<T>(values: readonly T[], field: string): readonly T[] {
  if (new Set(values).size !== values.length) {
    throw new ContractError(field, 'duplicate entries are not supported');
  }
  return values;
}
