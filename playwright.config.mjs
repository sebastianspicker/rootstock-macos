import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  timeout: 30000,
  fullyParallel: true,
  use: {
    browserName: 'chromium',
    channel: 'chrome',
    colorScheme: 'light',
    reducedMotion: 'reduce',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {name: 'desktop', use: {viewport: {width: 1440, height: 900}}},
    {name: 'compact', use: {viewport: {width: 1024, height: 768}}},
    {name: 'narrow', use: {viewport: {width: 320, height: 568}}},
  ],
});
