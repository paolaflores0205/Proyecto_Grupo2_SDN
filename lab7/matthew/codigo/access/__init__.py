"""Paquete unificado de autenticacion (R1) y autorizacion multitabla (R2) para Lab 7 - Grupo 2."""
from .auth import AuthResult, DUMMY_HASH, GENERIC_ERROR, UserStore, validate_credentials
from .authz import (
    CAMPUS_ROLES,
    ROLE_CODE_MAP,
    AccessDecision,
    AccessMatrix,
    Decision,
    Resource,
    build_campus_matrix,
    evaluate_access,
    normalize_role,
)
from .dti import DTIAccount, evaluate_dti_console_access
from .lockout import FailureStore, LoginGuard, MemoryFailureStore
from .mysql_adapters import MySQLFailureStore, MySQLUserStore, load_access_matrix_from_rows
from .passwords import hash_password, verify_password
from .translate import (
    DENY_PRIORITY,
    LMS_SHARED_PRIORITY,
    PERMIT_PRIORITY_BASE,
    PREFIX,
    Client,
    PolicyEntry,
    effective_actions,
    effective_table20_decision,
    session_context,
    translate_policy,
)

__all__ = [
    "AccessDecision",
    "AccessMatrix",
    "AuthResult",
    "CAMPUS_ROLES",
    "Client",
    "DENY_PRIORITY",
    "DTIAccount",
    "DUMMY_HASH",
    "Decision",
    "FailureStore",
    "GENERIC_ERROR",
    "LMS_SHARED_PRIORITY",
    "LoginGuard",
    "MemoryFailureStore",
    "MySQLFailureStore",
    "MySQLUserStore",
    "PERMIT_PRIORITY_BASE",
    "PREFIX",
    "PolicyEntry",
    "ROLE_CODE_MAP",
    "Resource",
    "UserStore",
    "build_campus_matrix",
    "effective_actions",
    "effective_table20_decision",
    "evaluate_access",
    "evaluate_dti_console_access",
    "hash_password",
    "load_access_matrix_from_rows",
    "normalize_role",
    "session_context",
    "translate_policy",
    "validate_credentials",
    "verify_password",
]
