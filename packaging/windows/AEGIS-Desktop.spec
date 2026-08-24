# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_root = Path(SPECPATH).resolve().parents[1]
version_file = project_root / "packaging" / "windows" / "version_info.txt"
icon_file = project_root / "packaging" / "windows" / "AEGIS.ico"

a = Analysis(
    [str(project_root / "desktop_main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / "web"), "web"),
        (str(project_root / "LICENSE.txt"), "."),
    ],
    hiddenimports=["webview.platforms.edgechromium"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["cefpython3", "gi", "PyQt5", "PyQt6", "PySide2", "PySide6"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AEGIS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_file) if icon_file.is_file() else None,
    version=str(version_file),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="AEGIS-Desktop",
)

