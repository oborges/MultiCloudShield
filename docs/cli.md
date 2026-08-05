# CLI

Configure remote commands with `MCS_SERVER_URL` and `MCS_API_TOKEN`. The URL must be HTTP(S) and may
not contain credentials.

```bash
mcs config show
mcs connection list
mcs connection add --provider aws --name prod --scope-id ACCOUNT_ID \
  --mechanism aws_default_chain
mcs connection test CONNECTION_UUID
mcs token create --name ci --role viewer --expires-days 30
mcs token list
mcs token revoke TOKEN_UUID
mcs scan start --connection CONNECTION_UUID --wait
mcs scan status SCAN_UUID
mcs findings list --severity high --output json
mcs findings show FINDING_UUID
mcs findings export --format csv --out findings.csv
mcs policy list
mcs policy validate
```

Local mode needs neither server nor database:

```bash
mcs scan --local --provider demo --scope deterministic-v1 --output json --out result.json
```

Exit codes: `0` completed, `2` finding met `--fail-on`, `3` request/scan failure, and `4` partial scan.
