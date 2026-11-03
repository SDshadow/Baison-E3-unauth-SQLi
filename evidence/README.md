# Evidence

Raw HTTP responses captured during verification, **with all hostnames redacted**.
These are verbatim excerpts; full unredacted records are kept privately by the
reporter and shared with the vendor / reviewing authority on request.

| File | Deployment | Shows |
|---|---|---|
| `e1-anonymous-sql-probe.redacted.txt` | two live deployments, productCode 1008 | `select 1 as e3probe` executed anonymously |
| `e2-db-identity.redacted.txt` | authorized demo deployment | `@@VERSION`, `SYSTEM_USER = sa`, `sysadmin = 1` |
| `e3-xpcmdshell-config.redacted.txt` | live deployment (1008) | `xp_cmdshell` enabled (`value_in_use = 1`); `EXEC` batch accepted |
| `e4-sysparam-disclosure.redacted.txt` | demo deployment | anonymous `SysParamInfo` full-parameter disclosure |

Screenshots may be added; the text excerpts above are the primary evidence.
