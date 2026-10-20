"""Encrypted credential records, resolved only by the execution layer.

The model never receives a secret. It may receive a ``credential_ref``; the owner
resolves that reference here, and only a record whose validation state is ``valid``
is handed to a command builder. Validation itself requires a target and evidence,
so an unproven candidate cannot be promoted by accident.
"""

from datetime import datetime
from hashlib import sha256
import os
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


SecretType = Literal["password", "ntlm", "ssh_key", "token"]
ValidationState = Literal["unverified", "valid", "invalid"]


class CredentialRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    credential_id: str
    principal: str
    secret_type: SecretType
    source_host: str
    source_artifact: str | None = None
    validation_state: ValidationState = "unverified"
    validated_at: datetime | None = None
    validation_target: str | None = None
    validation_evidence: dict | None = None


class ResolvedCredential(BaseModel):
    """A secret for one execution call; ``SecretStr`` keeps it out of repr/logs."""

    model_config = ConfigDict(extra="forbid")
    credential_id: str
    principal: str
    secret: SecretStr


class CredentialStore:
    def __init__(self, connection, *, key_path=None):
        self.connection = connection
        self.key_path = Path(key_path or os.environ.get(
            "AGV_CREDENTIAL_KEY_FILE", "data/credential.key"))
        self._fernet = Fernet(self._key())

    def _key(self) -> bytes:
        if self.key_path.exists():
            value = self.key_path.read_bytes().strip()
            if value:
                return value
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        value = Fernet.generate_key()
        self.key_path.write_bytes(value)
        try:
            self.key_path.chmod(0o600)
        except OSError:
            pass
        return value

    def setup(self) -> None:
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY CHECK (btrim(credential_id) <> ''),
                    principal TEXT NOT NULL CHECK (btrim(principal) <> ''),
                    secret_type TEXT NOT NULL
                        CHECK (secret_type IN ('password', 'ntlm', 'ssh_key', 'token')),
                    secret_ciphertext TEXT NOT NULL CHECK (btrim(secret_ciphertext) <> ''),
                    source_host TEXT NOT NULL CHECK (btrim(source_host) <> ''),
                    source_artifact TEXT,
                    validation_state TEXT NOT NULL DEFAULT 'unverified'
                        CHECK (validation_state IN ('unverified', 'valid', 'invalid')),
                    validated_at TIMESTAMPTZ,
                    validation_target TEXT,
                    validation_evidence JSONB,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS credentials_validation
                ON credentials (validation_state, validation_target)
            """)

    def commit(self) -> None:
        self.connection.commit()

    @staticmethod
    def credential_id(principal: str, source_host: str, secret: str) -> str:
        seed = "|".join((principal, source_host, secret))
        return "cred-" + sha256(seed.encode()).hexdigest()[:20]

    def put(self, *, principal: str, secret: str, secret_type: SecretType,
            source_host: str, source_artifact: str | None = None,
            credential_id: str | None = None) -> str:
        if not principal.strip() or not secret or not source_host.strip():
            raise ValueError("credential_principal_secret_host_required")
        credential_id = credential_id or self.credential_id(principal, source_host, secret)
        ciphertext = self._fernet.encrypt(secret.encode()).decode()
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("""
                INSERT INTO credentials
                    (credential_id, principal, secret_type, secret_ciphertext,
                     source_host, source_artifact)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (credential_id) DO NOTHING
            """, (credential_id, principal, secret_type, ciphertext,
                  source_host, source_artifact))
        return credential_id

    def get(self, credential_id: str) -> CredentialRecord | None:
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM credentials WHERE credential_id = %s", (credential_id,))
            row = cur.fetchone()
        return self._record(row) if row else None

    @staticmethod
    def _record(row) -> CredentialRecord:
        return CredentialRecord.model_validate({
            key: row[key] for key in CredentialRecord.model_fields if key in row})

    def resolve(self, credential_id: str, *, require_valid: bool = True,
                target: str | None = None) -> ResolvedCredential:
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM credentials WHERE credential_id = %s", (credential_id,))
            row = cur.fetchone()
        if row is None:
            raise KeyError(credential_id)
        record = self._record(row)
        if require_valid and record.validation_state != "valid":
            raise ValueError("credential_not_validated")
        if target and record.validation_target not in {None, "*", str(target)}:
            raise ValueError("credential_target_mismatch")
        secret = self._fernet.decrypt(row["secret_ciphertext"].encode()).decode()
        return ResolvedCredential(credential_id=record.credential_id,
                                  principal=record.principal, secret=SecretStr(secret))

    def mark_validated(self, credential_id: str, *, target: str, evidence: dict) -> None:
        """Promotion requires both the exact target and non-empty evidence."""
        if not str(target or "").strip() or not evidence:
            raise ValueError("credential_validation_target_and_evidence_required")
        self._set_state(credential_id, "valid", target, evidence)

    def mark_invalid(self, credential_id: str, *, target: str, evidence: dict) -> None:
        if not str(target or "").strip() or not evidence:
            raise ValueError("credential_validation_target_and_evidence_required")
        self._set_state(credential_id, "invalid", target, evidence)

    def _set_state(self, credential_id: str, state: ValidationState, target: str,
                   evidence: dict) -> None:
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("""
                UPDATE credentials
                SET validation_state = %s, validated_at = statement_timestamp(),
                    validation_target = %s, validation_evidence = %s
                WHERE credential_id = %s
            """, (state, target, Jsonb(evidence), credential_id))
            if cur.rowcount == 0:
                raise KeyError(credential_id)

    def delete(self, credential_id: str) -> None:
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("DELETE FROM credentials WHERE credential_id = %s", (credential_id,))
