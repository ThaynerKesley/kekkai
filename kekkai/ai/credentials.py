"""Opt-in Windows Credential Manager storage; never falls back to plaintext."""
from ..i18n import tr
import ctypes
import os
from ctypes import wintypes

from ..ai_providers import PROVIDERS


class CredentialError(RuntimeError):
    pass


class CREDENTIAL(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]


class WindowsCredentialStore:
    @property
    def available(self):
        return os.name == "nt"

    def _target(self, provider):
        if provider not in PROVIDERS:
            raise CredentialError(tr("Provider inválido."))
        return "Kekkai/AI/" + provider

    def _library(self):
        if not self.available:
            raise CredentialError(tr("Cofre Windows indisponível. A chave pode ser usada apenas em memória neste sistema."))
        library = ctypes.WinDLL("advapi32", use_last_error=True)
        library.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
        library.CredWriteW.restype = wintypes.BOOL
        library.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
        library.CredReadW.restype = wintypes.BOOL
        library.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        library.CredDeleteW.restype = wintypes.BOOL
        library.CredFree.argtypes = [ctypes.c_void_p]
        return library

    def save(self, provider: str, key: str):
        if not key.strip() or len(key.encode("utf-8")) > 2500 or "\n" in key or "\r" in key:
            raise CredentialError(tr("Chave vazia ou tamanho inválido."))
        library = self._library()
        payload = key.encode("utf-8")
        blob = ctypes.create_string_buffer(payload)
        credential = CREDENTIAL(Type=1, TargetName=self._target(provider), CredentialBlobSize=len(payload),
                                CredentialBlob=ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte)), Persist=2, UserName=provider)
        try:
            if not library.CredWriteW(ctypes.byref(credential), 0):
                raise CredentialError(tr("Não foi possível salvar no cofre do Windows."))
        finally:
            ctypes.memset(blob, 0, len(payload))

    def read(self, provider: str) -> str | None:
        library = self._library()
        pointer = ctypes.POINTER(CREDENTIAL)()
        if not library.CredReadW(self._target(provider), 1, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == 1168:
                return None
            raise CredentialError(tr("Não foi possível acessar o cofre do Windows."))
        try:
            value = pointer.contents
            return ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize).decode("utf-8")
        finally:
            library.CredFree(pointer)

    def configured(self, provider: str) -> bool:
        key = self.read(provider)
        present = bool(key)
        key = None
        return present

    def delete(self, provider: str):
        library = self._library()
        if not library.CredDeleteW(self._target(provider), 1, 0) and ctypes.get_last_error() != 1168:
            raise CredentialError(tr("Não foi possível remover a chave do cofre Windows."))
