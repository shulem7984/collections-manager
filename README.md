# Collections Company Manager — Starter Application

An English-language Flask/SQLite starter for managing client companies, customer accounts, account notes/history, collections, commission estimates, follow-ups, CSV/XLSX import and CSV export, reports, separate logins, and downloadable database backups.

## Important limitations

This is a working **starter project**, not yet a production-ready hosted service. It has not been independently security-audited. Do not upload real customer data to an unconfigured deployment. Before using it with live debtor/customer records, deploy it with HTTPS, a persistent database volume or managed database, a secret key supplied by the hosting platform, strong unique passwords, encrypted backups, tested restore procedures, monitoring, and appropriate legal/privacy controls. SQLite is intended for a small pilot; a hosted multi-user production deployment should generally use PostgreSQL. This starter intentionally does not process credit cards or store card details.

## Features in this starter

- Dashboard totals: companies, customer accounts, outstanding balances, total collections, estimated commissions.
- Client companies with contact details and commission rate.
- Customer accounts, balances, statuses, assigned employee, and next follow-up date.
- Timestamped account notes/history with the employee username.
- Collection entry that reduces the outstanding balance and closes a fully paid account.
- CSV and Excel (`.xlsx`) import for account lists and CSV export. Excel imports read the first worksheet.
- Date-filtered company reports and estimated commission.
- Separate password-hash-based logins; admin can create/disable users. Employees can view only assigned accounts in account lists, account detail pages, collections, follow-ups, exports, and reports. Only admins can assign/reassign accounts, manage client companies, import accounts, manage users, and download backups.
- CSRF token validation on forms, basic session-cookie settings, and a simple audit log.
- Admin-only database backup download.

## Run locally

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

Set environment variables before the first run. At minimum, set `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD` to unique values. For HTTPS production deployments, set `COOKIE_SECURE=1`. Do not use the fallback development password for real data. Then run:

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser. The database is created on first run. The initial admin account is created only if the users table is empty; changing environment variables after account creation does not change that account's password.

For a local LAN test only, change the `app.run` host to `0.0.0.0`. Do not expose the Flask development server directly to the public internet.

## Online deployment outline

1. Choose a trusted host that supports Python web applications, HTTPS, persistent storage, and scheduled backups.
2. Provision a managed PostgreSQL database for production. The included starter currently uses SQLite, so PostgreSQL support and migrations must be added before a serious multi-employee production launch.
3. Configure secrets in the host dashboard, not in source control. Set a strong `SECRET_KEY` and unique admin credentials.
4. Run behind a production WSGI server such as Waitress or Gunicorn and enforce HTTPS. Configure secure cookies and trusted proxy settings appropriate to the host.
5. Restrict admin access, test employee permissions, enable monitoring, schedule encrypted backups, and test restoring a backup before importing live data.
6. Have a qualified developer review access controls, audit logging, privacy/retention policies, and applicable collection laws before real use.

## CSV and Excel import

Upload either a CSV UTF-8 file or an Excel `.xlsx` workbook under Import Accounts. Excel imports read the first worksheet. Select the correct client company first. The importer recognizes common headers such as `customer_name`/`customer`/`name`, `account_number`, `phone`, `email`, `address`, `original_balance`, `balance`, `status`, and `next_followup`. Imports add new rows; they do not automatically deduplicate records.

## Suggested next production milestones

- PostgreSQL + migrations and automated tests.
- Password reset, MFA, login rate limiting, account lockout, and per-role/per-account authorization.
- Manager-friendly assignment workflows and permission regression tests.
- Immutable collection ledger and correction/reversal workflow rather than editing history.
- Commission rate snapshots per collection and configurable commission rules.
- XLSX import with column mapping, validation preview, duplicate detection, and import rollback.
- Automated follow-up reminders by email/SMS, if desired.
- Scheduled encrypted backups, retention policy, restore drills, and admin audit viewer.
- Payment processor integration only when selected; never store raw card numbers or CVV.
