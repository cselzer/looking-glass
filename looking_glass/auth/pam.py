"""PAM password check via libpam.

The wall process must be able to talk to PAM (often root or equivalent on
Linux pam_unix; OpenDirectory on macOS). Tests mock `authenticate`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from typing import Optional

PAM_SUCCESS = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4
PAM_CONV_ERR = 19
PAM_BUF_ERR = 5

SERVICE = "login"


class PamHandle(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_void_p)]


class PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]


CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(PamMessage)),
    ctypes.POINTER(ctypes.POINTER(PamResponse)),
    ctypes.c_void_p,
)


class PamConv(ctypes.Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


def _lib(name: str) -> Optional[ctypes.CDLL]:
    path = ctypes.util.find_library(name)
    if not path:
        return None
    try:
        return ctypes.CDLL(path)
    except OSError:
        return None


def _pam() -> Optional[ctypes.CDLL]:
    lib = _lib("pam")
    if lib is None:
        return None
    lib.pam_start.restype = ctypes.c_int
    lib.pam_start.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(PamConv),
        ctypes.POINTER(PamHandle),
    ]
    lib.pam_authenticate.restype = ctypes.c_int
    lib.pam_authenticate.argtypes = [PamHandle, ctypes.c_int]
    lib.pam_acct_mgmt.restype = ctypes.c_int
    lib.pam_acct_mgmt.argtypes = [PamHandle, ctypes.c_int]
    lib.pam_end.restype = ctypes.c_int
    lib.pam_end.argtypes = [PamHandle, ctypes.c_int]
    return lib


def authenticate(username: str, password: str, service: str = SERVICE) -> bool:
    """Return True if PAM accepts this local account password."""
    user = str(username or "")
    secret = str(password or "")
    if not user or not secret:
        return False
    lib = _pam()
    libc = _lib("c")
    if lib is None or libc is None:
        return False
    libc.malloc.restype = ctypes.c_void_p
    libc.malloc.argtypes = [ctypes.c_size_t]
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    secret_bytes = secret.encode("utf-8")

    @CONV_FUNC
    def conv(n_messages, messages, p_response, _app_data):
        if n_messages <= 0:
            return PAM_CONV_ERR
        size = ctypes.sizeof(PamResponse)
        raw = libc.calloc(n_messages, size)
        if not raw:
            return PAM_BUF_ERR
        p_response[0] = ctypes.cast(raw, ctypes.POINTER(PamResponse))
        arr = ctypes.cast(raw, ctypes.POINTER(PamResponse))
        for i in range(n_messages):
            style = messages[i].contents.msg_style
            arr[i].resp_retcode = 0
            arr[i].resp = None
            if style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                buf = libc.malloc(len(secret_bytes) + 1)
                if not buf:
                    return PAM_BUF_ERR
                ctypes.memmove(buf, secret_bytes, len(secret_bytes))
                end = ctypes.c_void_p(int(buf) + len(secret_bytes))
                ctypes.memset(end, 0, 1)
                arr[i].resp = ctypes.cast(buf, ctypes.c_char_p)
        return PAM_SUCCESS

    handle = PamHandle()
    conversation = PamConv(conv, None)
    status = lib.pam_start(
        service.encode("ascii"),
        user.encode("utf-8"),
        ctypes.byref(conversation),
        ctypes.byref(handle),
    )
    if status != PAM_SUCCESS:
        if handle.handle:
            lib.pam_end(handle, status)
        return False
    status = lib.pam_authenticate(handle, 0)
    if status == PAM_SUCCESS:
        status = lib.pam_acct_mgmt(handle, 0)
    lib.pam_end(handle, status)
    return status == PAM_SUCCESS
