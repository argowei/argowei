import { TestScheduler } from 'rxjs/testing';

import { poll } from './poll';

describe('poll', () => {
  const scheduler = () => new TestScheduler((actual, expected) => expect(actual).toEqual(expected));

  it('ticks now and then on every interval', () => {
    scheduler().run(({ expectObservable }) => {
      expectObservable(poll(10), '^ 25ms !').toBe('a 9ms b 9ms c', { a: 0, b: 1, c: 2 });
    });
  });

  it('can wait for the first interval', () => {
    scheduler().run(({ expectObservable }) => {
      expectObservable(poll(10, { immediate: false }), '^ 25ms !').toBe('10ms a 9ms b', {
        a: 0,
        b: 1,
      });
    });
  });

  it('ticks once, or never, when polling is off', () => {
    scheduler().run(({ expectObservable }) => {
      expectObservable(poll(0)).toBe('(a|)', { a: 0 });
      expectObservable(poll(0, { immediate: false })).toBe('|');
    });
  });
});
