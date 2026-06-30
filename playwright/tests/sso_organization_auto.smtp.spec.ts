import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import * as orgs from './setups/orgs';
import { logNewUser, logUser } from './setups/sso';

// TODO: replace these local MailDev types with upstream typings when the package exports them cleanly.
type MailMessage = { subject?: string; html: string | false };
type MailBuffer = { close: () => void; expect: (filter: (mail: MailMessage) => boolean) => Promise<MailMessage> };
type MailServer = { buffer: (subject: string) => MailBuffer; listen: () => Promise<void>; close: () => Promise<void> };
type TestUser = { email: string; name: string; password: string };
type TestUsers = { user1: TestUser; user2: TestUser; user3: TestUser };

// TODO: tighten the env loader typing in global-utils.ts once the broader Playwright helpers are cleaned up.
const users = utils.loadEnv() as TestUsers;
const maildevSmtpPort = Number(process.env.MAILDEV_SMTP_PORT);
const maildevHttpPort = Number(process.env.MAILDEV_HTTP_PORT);

let mailServer!: MailServer;
let mail1Buffer!: MailBuffer;
let mail2Buffer!: MailBuffer;
let mail3Buffer!: MailBuffer;
let defaultOrgId = '';
let defaultOrgKey = '';

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    if (Number.isNaN(maildevSmtpPort) || Number.isNaN(maildevHttpPort)) {
        throw new Error('MailDev ports must be configured as numeric values');
    }

    mailServer = new MailDev({
        port: maildevSmtpPort,
        web: { port: maildevHttpPort },
    });

    await mailServer.listen();

    await utils.startVault(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
        SSO_ENABLED: true,
        SSO_ONLY: true,
    });

    mail1Buffer = mailServer.buffer(users.user1.email);
    mail2Buffer = mailServer.buffer(users.user2.email);
    mail3Buffer = mailServer.buffer(users.user3.email);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    await Promise.all([
        mail1Buffer?.close(),
        mail2Buffer?.close(),
        mail3Buffer?.close(),
        mailServer?.close(),
    ]);
});

test('Bootstrap default org and SSO reconciliation', async ({ page }, testInfo: TestInfo) => {
    await logNewUser(test, page, users.user1, { mailBuffer: mail1Buffer });
    await logNewUser(test, page, users.user3, { mailBuffer: mail3Buffer });

    defaultOrgId = await orgs.create(test, page, '/Test');
    defaultOrgKey = await orgs.getOrganizationKey(test, page, defaultOrgId);
    await orgs.members(test, page, '/Test');
    await orgs.invite(test, page, '/Test', users.user3.email);
    await mail3Buffer.expect((m) => m.subject === 'Join /Test');

    await utils.restartVault(
        page,
        testInfo,
        {
            SMTP_HOST: process.env.MAILDEV_HOST,
            SMTP_FROM: process.env.PW_SMTP_FROM,
            SSO_ENABLED: true,
            SSO_ONLY: true,
            SSO_DEFAULT_ORG_ID: defaultOrgId,
            SSO_ORG_AUTO_PROVISION: true,
            SSO_ORG_INVITE_AUTO_ACCEPT: true,
            SSO_ORG_AUTO_CONFIRM: true,
            SSO_ORG_AUTO_CONFIRM_KEY: defaultOrgKey,
        },
        false,
    );
});

test('New SSO user is auto provisioned once', async ({ page }) => {
    await logNewUser(test, page, users.user2, { mailBuffer: mail2Buffer });

    await logUser(test, page, users.user2, { mailBuffer: mail2Buffer });

    await logUser(test, page, users.user1);
    await orgs.members(test, page, '/Test');
    const user2Row = page.getByRole('row').filter({ hasText: users.user2.email });
    await expect(user2Row).toHaveCount(1);
    await expect(user2Row).not.toHaveText(/Needs confirmation|Invited/);

    await logUser(test, page, users.user2);
    await page.getByRole('button', { name: 'vault: /Test', exact: true }).click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});

test('Invited SSO user is reconciled', async ({ page }) => {
    await logUser(test, page, users.user3, { mailBuffer: mail3Buffer });

    await mail1Buffer.expect((m) => m.subject === 'Invitation to /Test accepted');
    await mail3Buffer.expect((m) => m.subject === 'Invitation to /Test confirmed');

    await logUser(test, page, users.user1);
    await orgs.members(test, page, '/Test');
    await expect(page.getByRole('row').filter({ hasText: users.user3.email })).not.toHaveText(/Needs confirmation|Invited/);

    await logUser(test, page, users.user3);
    await page.getByRole('button', { name: 'vault: /Test', exact: true }).click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});
