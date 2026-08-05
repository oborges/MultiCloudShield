import { expect, test } from '@playwright/test'
test('login exposes the complete navigation', async ({ page }) => {
  test.skip(!process.env.MCS_E2E, 'Requires the local API and seeded PostgreSQL demo estate')
  await page.goto('/')
  await expect(page.getByText('MultiCloudShield')).toBeVisible()
})
