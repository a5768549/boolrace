# Responsible use and reporting

Use boolrace only in the supplied disposable local lab or on systems whose owner has explicitly authorized the exact testing scope. Permission to view a website is not permission to query its database. The MIT license grants software rights, not authority to test someone else's system.

Before authorized testing, agree on the endpoint and tables, schedule, request budget, stop conditions, data retention, and reporting channel. Start conservatively and stop on instability, access outside the agreed scope, or unexpected real data. The engine is not a production-safe scanner.

Do not expose the intentionally vulnerable lab to a LAN, the Internet, reverse proxies, port-forwarding services, or shared untrusted users. Do not point it at a production database. Its published login and seed values exist solely for a disposable synthetic fixture.

## Data hygiene

Output files, configurations, headers, logs, fingerprints, and reports may contain sensitive data outside the fixture. Store them with appropriate local permissions and retention. Never commit target URLs, cookies, tokens, credentials, account identifiers, or extracted production data. `.gitignore` helps prevent mistakes; it is not a security control and does not untrack already committed files.

## Bug reports

For ordinary bugs, provide a minimal reproduction using the shipped synthetic fixture, repository revision, exact commands, Python/DB versions, and sanitized failure details. State whether the issue reproduces against a real DB or only a unit-test fixture.

For a potential security vulnerability, use GitHub's private vulnerability reporting channel **if enabled**. If it is unavailable, ask the maintainer for a private reporting route without posting exploit details or sensitive data publicly. No dedicated private-reporting service or response-time commitment is claimed here.
