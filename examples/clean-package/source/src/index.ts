// Source implementation
import debug from 'debug';
const log = debug('sample:app');

export function compute(a: number, b: number): number {
    log('computing sum');
    return a + b;
}
