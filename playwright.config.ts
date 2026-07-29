import {defineConfig} from '@playwright/test';

const browserPath = process.env.ROOTSTOCK_BROWSER_PATH;

export default defineConfig({
  testDir: './tests/browser',
  timeout: 30000,
  fullyParallel: true,
  use: {
    browserName: 'chromium',
    colorScheme: 'light',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    ...(browserPath ? {launchOptions: {executablePath: browserPath}} : {}),
  },
  projects: [
    {name: 'desktop', use: {viewport: {width: 1440, height: 900}}},
    {name: 'compact', use: {viewport: {width: 1024, height: 768}}},
    {name: 'narrow', use: {viewport: {width: 320, height: 568}}},
  ],
});
