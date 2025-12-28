#!/usr/bin/env python3
"""
aws_credproc_chain.py

AWS credential_process helper:
- Uses a source profile (long-lived keys) from ~/.aws/credentials
- Prompts for MFA and calls STS GetSessionToken (cached)
- Optionally chains 1..N AssumeRole hops (cached final output)
- Prints credential_process JSON to stdout

Requires: boto3 (and its botocore) available to the Python interpreter running this script.
Install if needed: pip3 install --user boto3

Example (AWS config):
  credential_process = python3 /usr/local/bin/aws_credproc_chain.py \
    --source-profile orgA-long \
    --mfa-serial arn:aws:iam::111111111111:mfa/mydevice \
    --session-duration 43200 \
    --role arn:aws:iam::222222222222:role/JumpRole \
    --role arn:aws:iam::333333333333:role/FinalAdminRole
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except Exception as e:
    print(
        "ERROR: boto3/botocore not available to this python3 interpreter.\n"
        "Install with: pip3 install --user boto3\n"
        f"Details: {e}",
        file=sys.stderr,
    )
    sys.exit(1)


@dataclass(frozen=True)
class ProcResult:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime  # UTC


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_aws_iso8601(s: str) -> datetime:
    """
    AWS often returns '2025-12-28T14:03:11Z' or with +00:00.
    """
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def _dt_to_aws_iso8601(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    # Emit with 'Z' for compatibility
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _cache_dir() -> Path:
    root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    d = Path(root) / "aws-credproc"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_key(data: Dict[str, Any]) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()


def _load_cache(cache_file: Path) -> Optional[Dict[str, Any]]:
    if not cache_file.exists():
        return None
    try:
        with cache_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _cache_valid(cached: Dict[str, Any], refresh_skew_seconds: int) -> bool:
    try:
        exp = _parse_aws_iso8601(cached["Expiration"])
        now = _utcnow()
        # refresh early
        return (now.timestamp() + refresh_skew_seconds) < exp.timestamp()
    except Exception:
        return False


def _write_cache_atomic(cache_file: Path, obj: Dict[str, Any]) -> None:
    tmp = cache_file.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(cache_file)


def _mk_sts_client(
        *,
        profile_name: Optional[str] = None,
        region: Optional[str] = None,
        creds: Optional[ProcResult] = None,
        timeout_seconds: int = 30,
) :
    """
    Create an STS client either from a named profile or from explicit session creds.
    """
    boto_cfg = BotoConfig(
        region_name=region,
        connect_timeout=timeout_seconds,
        read_timeout=timeout_seconds,
        retries={"max_attempts": 3, "mode": "standard"},
    )

    if creds is None:
        # Use the shared config/credentials chain for this profile
        sess = boto3.Session(profile_name=profile_name, region_name=region)
        return sess.client("sts", config=boto_cfg)

    # Use explicit credentials (for chaining)
    sess = boto3.Session(
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        aws_session_token=creds.session_token,
        region_name=region,
    )
    return sess.client("sts", config=boto_cfg)


def _get_session_token_with_mfa(
        *,
        source_profile: str,
        mfa_serial: str,
        session_duration: int,
        region: Optional[str],
        token_code: Optional[str],
) -> ProcResult:
    if token_code is None:
        if not _is_tty():
            raise RuntimeError("MFA required but no TTY is available to prompt for code.")
        token_code = getpass(f"MFA code for {mfa_serial}: ")

    sts = _mk_sts_client(profile_name=source_profile, region=region)

    try:
        resp = sts.get_session_token(
            SerialNumber=mfa_serial,
            TokenCode=token_code,
            DurationSeconds=session_duration,
        )
    except ClientError as e:
        raise RuntimeError(f"GetSessionToken failed: {e}")

    c = resp["Credentials"]
    return ProcResult(
        access_key_id=c["AccessKeyId"],
        secret_access_key=c["SecretAccessKey"],
        session_token=c["SessionToken"],
        expiration=c["Expiration"].astimezone(timezone.utc)
        if isinstance(c["Expiration"], datetime)
        else _parse_aws_iso8601(str(c["Expiration"])),
    )


def _assume_role(
        *,
        prior: ProcResult,
        role_arn: str,
        role_session_name: str,
        duration: int,
        region: Optional[str],
        external_id: Optional[str],
) -> ProcResult:
    sts = _mk_sts_client(creds=prior, region=region)

    kwargs: Dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name,
        "DurationSeconds": duration,
    }
    if external_id:
        kwargs["ExternalId"] = external_id

    try:
        resp = sts.assume_role(**kwargs)
    except ClientError as e:
        raise RuntimeError(f"AssumeRole failed for {role_arn}: {e}")

    c = resp["Credentials"]
    return ProcResult(
        access_key_id=c["AccessKeyId"],
        secret_access_key=c["SecretAccessKey"],
        session_token=c["SessionToken"],
        expiration=c["Expiration"].astimezone(timezone.utc)
        if isinstance(c["Expiration"], datetime)
        else _parse_aws_iso8601(str(c["Expiration"])),
    )


def _emit_credential_process_json(result: ProcResult) -> Dict[str, Any]:
    return {
        "Version": 1,
        "AccessKeyId": result.access_key_id,
        "SecretAccessKey": result.secret_access_key,
        "SessionToken": result.session_token,
        "Expiration": _dt_to_aws_iso8601(result.expiration),
    }


def main() -> int:
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--source-profile", required=True, help="Profile with long-lived keys in ~/.aws/credentials")
    p.add_argument("--mfa-serial", required=True, help="MFA device ARN (arn:aws:iam::ACCOUNT:mfa/DEVICE)")
    p.add_argument("--session-duration", type=int, default=43200, help="GetSessionToken duration seconds")
    p.add_argument("--role", action="append", default=[], help="Role ARN hop (can be repeated for chaining)")
    p.add_argument("--role-duration", type=int, default=43200, help="AssumeRole duration seconds per hop")
    p.add_argument("--role-session-name", default="credproc", help="Base role session name (suffixes added per hop)")
    p.add_argument("--external-id", default=None, help="ExternalId for AssumeRole (applies to all hops)")
    p.add_argument("--region", default=None, help="Region for STS calls (optional)")
    p.add_argument("--refresh-skew", type=int, default=60, help="Refresh creds this many seconds before expiration")
    p.add_argument("--no-cache", action="store_true", help="Disable cache (always prompt/call STS)")
    p.add_argument("--mfa-code", default=None, help="MFA code (optional; if omitted, prompt)")
    args = p.parse_args()

    # Cache key must include everything that changes output
    cache_input = {
        "source_profile": args.source_profile,
        "mfa_serial": args.mfa_serial,
        "session_duration": args.session_duration,
        "roles": args.role,
        "role_duration": args.role_duration,
        "role_session_name": args.role_session_name,
        "external_id": args.external_id,
        "region": args.region,
        # Note: mfa_code intentionally NOT included (it changes per run)
    }
    cache_file = _cache_dir() / f"{_cache_key(cache_input)}.json"

    if not args.no_cache:
        cached = _load_cache(cache_file)
        if cached and _cache_valid(cached, args.refresh_skew):
            sys.stdout.write(json.dumps(cached, indent=2, sort_keys=True) + "\n")
            return 0

    # 1) MFA session token from source profile
    try:
        base = _get_session_token_with_mfa(
            source_profile=args.source_profile,
            mfa_serial=args.mfa_serial,
            session_duration=args.session_duration,
            region=args.region,
            token_code=args.mfa_code,
        )
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # 2) Role chaining (0..N hops)
    cur = base
    for i, role_arn in enumerate(args.role, start=1):
        # Make the session name unique per hop and per process
        # Keep it short-ish (AWS limits RoleSessionName length)
        hop_name = f"{args.role_session_name}-{i}-{int(time.time())}"
        try:
            cur = _assume_role(
                prior=cur,
                role_arn=role_arn,
                role_session_name=hop_name,
                duration=args.role_duration,
                region=args.region,
                external_id=args.external_id,
            )
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    out = _emit_credential_process_json(cur)

    if not args.no_cache:
        _write_cache_atomic(cache_file, out)

    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
