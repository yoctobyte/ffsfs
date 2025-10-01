# crossfuse.py
# Crux compagis FUSE — fusepy in POSIX, WinFsp in Windows (per winfspy).
# Omnia commentaria Latine: succinta sed utilia.

from __future__ import annotations
import sys
import os
from typing import Any, Optional, Iterator, Tuple

# ---------- Commune ----------
class FuseOSError(OSError):
    """Error FUSE-similis ad usum communem."""
    pass

IS_WINDOWS = (sys.platform == "win32")

# ---------- POSIX: re-exporta fusepy ----------
if not IS_WINDOWS:
    # Nota: hoc nihil mutat in codice principali (API idem).
    from fuse import FUSE, Operations, FuseOSError as _FuseOSError  # type: ignore
    FuseOSError = _FuseOSError  # conserva semantica
else:
    # ---------- Windows: WinFsp per winfspy ----------
    import errno
    import stat
    import ctypes
    import string
    import winfspy
    from winfspy.plumbing import FileSystemOperations

    # ====== Utilitates systematis ======
    def _is_dir(st_mode: int) -> bool:
        return stat.S_ISDIR(st_mode)

    def _attr_from_mode(st_mode: int) -> int:
        attr = 0
        if _is_dir(st_mode):
            attr |= winfspy.FILE_ATTRIBUTE_DIRECTORY
        else:
            attr |= winfspy.FILE_ATTRIBUTE_ARCHIVE
        return attr

    def _coerce_int(x: Any, default: int = 0) -> int:
        try:
            return int(x)
        except Exception:
            return default

    # ----- Litterae curruntne? -----
    def _used_drive_bitmap() -> int:
        # GetLogicalDrives → bitmask (bit0 = A, bit1 = B, …)
        return ctypes.windll.kernel32.GetLogicalDrives()

    def _is_drive_free(letter: str) -> bool:
        letter = (letter.rstrip(":") + ":").upper()
        bitmask = _used_drive_bitmap()
        idx = ord(letter[0]) - ord('A')
        return ((bitmask >> idx) & 1) == 0

    def _choose_free_drive(prefer: Optional[str] = None) -> str:
        # Primo tenta praelatam, deinde D..Z (A/B saepe historice reservantur)
        if prefer:
            cand = (prefer.rstrip(":") + ":").upper()
            if cand[0] in string.ascii_uppercase and _is_drive_free(cand):
                return cand
        for ch in string.ascii_uppercase:
            if ch in ("A", "B"):   # fax mentis: A/B floppy/rezervata
                continue
            cand = f"{ch}:"
            if _is_drive_free(cand):
                return cand
        raise RuntimeError("Nulla littera libera reperta (A..Z)")

    def _normalize_mountpoint(mp: Optional[str]) -> Tuple[str, bool]:
        """
        Redde (mountpoint, is_drive_letter).
        Accepta:
          - 'AUTO' | 'AUTO:'  → selige litteram liberam
          - 'X' | 'X:'        → uteris littera (si libera)
          - 'C:\\via\\mons'   → ut radix directory (WinFsp mount path)
        """
        if not mp or mp.strip().upper() in ("AUTO", "AUTO:"):
            return (_choose_free_drive(None), True)
        s = mp.strip()
        # Solo littera?
        if len(s) == 1 and s.isalpha():
            s = s + ":"
        # Littera cum colon?
        if len(s) == 2 and s[1] == ":" and s[0].isalpha():
            s = s.upper()
            if not _is_drive_free(s):
                raise RuntimeError(f"Drive littera iam adhibetur: {s}")
            return (s, True)
        # Alias: path absolutus
        s = os.path.abspath(s)
        return (s, False)

    # ====== Adapter: fusepy ↔ WinFsp ======
    class _WinFspAdapter(FileSystemOperations):
        """
        Conversor qui capit classem 'Operations' (fusepy-styli) et
        eam exhibet methodis WinFsp.
        """
        def __init__(self, ops: "Operations"):
            super().__init__()
            self.ops = ops

        # --- Metadata ---
        def get_file_info(self, path: str, file_info: Any) -> None:
            try:
                st = self.ops.getattr(path)
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)
            except Exception:
                raise FuseOSError(errno.EIO)

            st_mode = _coerce_int(st.get("st_mode", 0))
            st_size = _coerce_int(st.get("st_size", 0))
            file_info.file_size = 0 if _is_dir(st_mode) else st_size
            file_info.allocation_size = file_info.file_size
            file_info.file_attributes = _attr_from_mode(st_mode)

            # TODO: Convertere epocha → FILETIME si opus est
            file_info.creation_time = 0
            file_info.last_access_time = 0
            file_info.last_write_time = 0
            file_info.change_time = 0

        # --- Enumerationes directory ---
        def enum_directory(self, path: str, marker: Optional[str]) -> Iterator[Tuple[str, Any]]:
            try:
                for name in self.ops.readdir(path, fh=None):
                    if name in (".", ".."):
                        continue
                    child = path.rstrip("/") + ("" if path == "/" else "/") + name
                    try:
                        st = self.ops.getattr(child)
                        st_mode = _coerce_int(st.get("st_mode", 0))
                        st_size = _coerce_int(st.get("st_size", 0))
                        entry = {
                            "file_attributes": _attr_from_mode(st_mode),
                            "allocation_size": 0 if _is_dir(st_mode) else st_size,
                            "file_size": 0 if _is_dir(st_mode) else st_size,
                            "creation_time": 0,
                            "last_access_time": 0,
                            "last_write_time": 0,
                        }
                    except Exception:
                        entry = {
                            "file_attributes": winfspy.FILE_ATTRIBUTE_ARCHIVE,
                            "allocation_size": 0,
                            "file_size": 0,
                            "creation_time": 0,
                            "last_access_time": 0,
                            "last_write_time": 0,
                        }
                    yield (name, entry)
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        # --- Aperire/Creare ---
        def open(self, path: str, access: int, share: int, create: int, options: int, context: Any) -> Any:
            O_RDONLY = 0
            O_WRONLY = 1
            O_RDWR   = 2
            O_CREAT  = 0x40
            O_TRUNC  = 0x200
            flags = O_RDONLY
            if access & (winfspy.FILE_GENERIC_WRITE | winfspy.FILE_WRITE_DATA | winfspy.FILE_APPEND_DATA):
                flags = O_RDWR
            if create in (winfspy.FILE_CREATE, winfspy.FILE_SUPERSEDE, winfspy.FILE_OPEN_IF):
                flags |= O_CREAT
            if create in (winfspy.FILE_SUPERSEDE, winfspy.FILE_OVERWRITE, winfspy.FILE_OVERWRITE_IF):
                flags |= O_TRUNC
            try:
                fh = self.ops.open(path, flags)
            except AttributeError:
                fh = None
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)
            return fh

        # --- Lectio/Scriptio ---
        def read(self, path: str, offset: int, size: int, context: Any) -> bytes:
            try:
                return self.ops.read(path, size, offset, getattr(context, "fh", None))
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        def write(self, path: str, offset: int, data: bytes, context: Any) -> int:
            try:
                return self.ops.write(path, data, offset, getattr(context, "fh", None))
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        # --- Magnitudo/Truncatio/Flush ---
        def set_file_size(self, path: str, new_size: int, context: Any) -> None:
            try:
                return self.ops.truncate(path, new_size, getattr(context, "fh", None))
            except AttributeError:
                return None
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        def flush_file_buffers(self, path: str, context: Any) -> None:
            try:
                if hasattr(self.ops, "flush"):
                    return self.ops.flush(path, getattr(context, "fh", None))
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        # --- Mutationes ---
        def create_directory(self, path: str, file_attributes: int, security_descriptor: Any, context: Any) -> None:
            try:
                return self.ops.mkdir(path, 0o777)
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        def delete(self, path: str) -> None:
            try:
                st = self.ops.getattr(path)
                if _is_dir(_coerce_int(st.get("st_mode", 0))):
                    return self.ops.rmdir(path)
                return self.ops.unlink(path)
            except FuseOSError as e:
                raise e
            except FileNotFoundError:
                raise FuseOSError(errno.ENOENT)
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        def rename(self, old_path: str, new_path: str, replace_if_exists: bool) -> None:
            try:
                return self.ops.rename(old_path, new_path)
            except FuseOSError as e:
                raise e
            except OSError as e:
                raise FuseOSError(e.errno or errno.EIO)

        # --- Tempora/Attributa (minime) ---
        def set_basic_info(
            self, path: str, file_attributes: int, creation_time: int,
            last_access_time: int, last_write_time: int, change_time: int, context: Any
        ) -> None:
            try:
                if hasattr(self.ops, "utimens"):
                    self.ops.utimens(path, (0, 0))  # TODO: mappare si opus est
            except Exception:
                pass

    # ====== API superficies (compat cum fusepy) ======
    class Operations:  # pragma: no cover
        """Basis vacua quae imitat 'fuse.Operations'."""
        pass

    def FUSE(ops: Operations, mountpoint: Optional[str], foreground: bool = True, **kwargs: Any) -> None:
        """
        Compat layer:
          - mountpoint: 'AUTO' | 'X:' | 'C:\\via\\mons'
          - foreground: in Windows simpliciter retinet event loop in hoc processu.
          - kwargs: 'allow_other' etc. (silentio ignoramus)
        """
        mp, is_drive = _normalize_mountpoint(mountpoint or "AUTO")
        adapter = _WinFspAdapter(ops)
        # Nota: WinFsp curat utrimque (drive letter vel path).
        with winfspy.Mount(adapter, mountpoint=mp, foreground=foreground):
            winfspy.run()

    # Unmount utilitas (commodum in scriptis)
    def unmount(mountpoint: str) -> None:
        """
        Conatus demontandi. Si drive letter, WinFsp liberabit cum processu exit.
        Hic functio est no-op placeholder ad symmetriam.
        """
        # In multis casibus, claudere processum sufficit. Retinemus pro API sim.
        return

