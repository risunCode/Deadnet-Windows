# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Collect all files from web folder
web_datas = []
web_datas.append(('web/templates/*', 'web/templates'))
web_datas.append(('web/static/css/*', 'web/static/css'))
web_datas.append(('web/static/js/*', 'web/static/js'))

# Collect utils module
utils_datas = [('utils/*', 'utils')]

a = Analysis(
    ['main_webview.py'],
    pathex=[],
    binaries=[],
    datas=web_datas + utils_datas,
    hiddenimports=[
        'scapy.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.layers.l2',
        'netifaces2',
        'flask',
        'flask_cors',
        'webview',
        'utils',
        'utils.attacker',
        'utils.api_routes',
        'utils.defines',
        'utils.misc_utils',
        'utils.network_utils',
        'utils.output_manager',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='DeadNet_Attacker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Keep console=True, will hide programmatically after GUI launch
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    uac_admin=True,  # Request admin privileges
)
