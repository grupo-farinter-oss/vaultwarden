import { expect, type Browser,Page } from '@playwright/test';

import * as utils from '../../global-utils';

export async function create(test, page: Page, name: string) {
    return test.step('Create Org', async () => {
        await page.locator('a').filter({ hasText: 'Password Manager' }).first().click();
        await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
        await page.getByRole('link', { name: 'New organisation' }).click();
        await page.getByLabel('Organisation name (required)').fill(name);
        await page.getByRole('button', { name: 'Submit' }).click();

        await utils.checkNotification(page, 'Organisation created');

        let orgId = page.url().match(/organizations\/([^/?#]+)/)?.[1];
        if (!orgId) {
            const orgHref = await page.locator('a[href*="/organizations/"]').filter({ hasText: name }).first().getAttribute('href');
            orgId = orgHref?.match(/organizations\/([^/?#]+)/)?.[1];
        }

        if (!orgId) {
            throw new Error(`Unable to determine created organization id from URL: ${page.url()}`);
        }

        return orgId;
    });
}

export async function getOrganizationKey(test, page: Page, orgId: string) {
    return test.step('Read organization key from web vault storage', async () => {
        const orgKey = await page.evaluate(async (targetOrgId) => {
            const isValidOrgKey = (value: unknown): value is string => {
                if (typeof value !== 'string') {
                    return false;
                }

                try {
                    const decoded = atob(value);
                    return decoded.length === 32 || decoded.length === 64;
                } catch {
                    return false;
                }
            };

            const keyFromValue = (value: unknown): string | null => {
                if (isValidOrgKey(value)) {
                    return value;
                }

                if (!value || typeof value !== 'object') {
                    return null;
                }

                const record = value as Record<string, unknown>;
                if (isValidOrgKey(record.keyB64)) {
                    return record.keyB64;
                }

                return null;
            };

            const findInTree = (value: unknown, seen = new Set<unknown>()): string | null => {
                if (!value || typeof value !== 'object' || seen.has(value)) {
                    return null;
                }
                seen.add(value);

                const record = value as Record<string, unknown>;
                const direct = keyFromValue(record[targetOrgId]);
                if (direct) {
                    return direct;
                }

                for (const child of Object.values(record)) {
                    const nested = findInTree(child, seen);
                    if (nested) {
                        return nested;
                    }
                }

                return null;
            };

            const parse = (value: string) => {
                try {
                    return JSON.parse(value);
                } catch {
                    return value;
                }
            };

            for (let index = 0; index < localStorage.length; index++) {
                const storageKey = localStorage.key(index);
                if (!storageKey) {
                    continue;
                }
                const found = findInTree(parse(localStorage.getItem(storageKey) ?? ''));
                if (found) {
                    return found;
                }
            }

            if (!indexedDB.databases) {
                return null;
            }

            for (const dbInfo of await indexedDB.databases()) {
                if (!dbInfo.name) {
                    continue;
                }

                const found = await new Promise<string | null>((resolve) => {
                    const open = indexedDB.open(dbInfo.name as string);
                    open.onerror = () => resolve(null);
                    open.onsuccess = () => {
                        const db = open.result;
                        const stores = Array.from(db.objectStoreNames);
                        if (!stores.length) {
                            db.close();
                            resolve(null);
                            return;
                        }

                        const tx = db.transaction(stores, 'readonly');
                        let remaining = stores.length;
                        let resolved = false;
                        const finish = (value: string | null) => {
                            if (resolved) {
                                return;
                            }
                            if (value || --remaining === 0) {
                                resolved = true;
                                db.close();
                                resolve(value);
                            }
                        };

                        for (const storeName of stores) {
                            const request = tx.objectStore(storeName).getAll();
                            request.onerror = () => finish(null);
                            request.onsuccess = () => finish(findInTree(request.result));
                        }
                    };
                });

                if (found) {
                    return found;
                }
            }

            return null;
        }, orgId);

        if (!orgKey) {
            throw new Error(`Unable to find organization key for ${orgId} in web vault storage`);
        }

        return orgKey;
    });
}

export async function policies(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} policies`, async () => {
        await page.locator('a').filter({ hasText: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click();
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('button', { name: 'Toggle collapse Settings' }).click();
        await page.getByRole('link', { name: 'Policies' }).click();
        await expect(page.getByRole('heading', { name: 'Policies' })).toBeVisible();
    });
}

export async function members(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} members`, async () => {
        await page.locator('a').filter({ hasText: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click();
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.locator('div').filter({ hasText: 'Members' }).nth(2).click();
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await expect(page.getByRole('cell', { name: 'All' })).toBeVisible();
    });
}

export async function invite(test, page: Page, name: string, email: string) {
    await test.step(`Invite ${email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByLabel('Email (required)').fill(email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.getByRole('combobox', { name: 'Permission' }).click();
        await page.getByText('Edit items', { exact: true }).click();
        await page.getByLabel('Select collections').click();
        await page.getByText('Default collection').click();
        await page.getByRole('cell', { name: 'Collection', exact: true }).click();
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'User(s) invited');
    });
}

export async function confirm(test, page: Page, name: string, user_email: string) {
    await test.step(`Confirm ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await expect(page.getByRole('heading', { name: 'Confirm user' })).toBeVisible();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await utils.checkNotification(page, 'confirmed');
    });
}

export async function revoke(test, page: Page, name: string, user_email: string) {
    await test.step(`Revoke ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Revoke access' }).click();
        await expect(page.getByRole('heading', { name: 'Revoke access' })).toBeVisible();
        await page.getByRole('button', { name: 'Revoke access' }).click();
        await utils.checkNotification(page, 'Revoked organisation access');
    });
}
