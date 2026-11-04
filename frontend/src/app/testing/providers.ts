import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { EnvironmentProviders, Provider } from '@angular/core';
import { provideRouter } from '@angular/router';

/**
 * What a page component needs in a test: an HttpClient backed by
 * `HttpTestingController`, and a router so `routerLink` works.
 */
export function providePageTesting(): (Provider | EnvironmentProviders)[] {
  return [provideHttpClient(), provideHttpClientTesting(), provideRouter([])];
}

/** Waits for pending timers and promises, e.g. after a flushed request. */
export const sleep = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));
