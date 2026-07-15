# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path

tools_root = Path(SPECPATH).parent / 'lau_tools'


a = Analysis(
    ['starter.py'],
    pathex=[],
    binaries=[],
    datas=[(str(tools_root), 'lau_tools')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='StarterCLI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
