"""
CAIP Universal Application & Web Browser Catalog & Discovery
===========================================================
Discovers all currently running user applications and web sessions on the host,
and provides clean universal mapping for live Sysmon telemetry.
"""

import os
import io
import csv
import subprocess
from typing import Dict, List, Any, Tuple

# Comprehensive Web Browser Executables
BROWSERS: Dict[str, Tuple[str, str, str]] = {
    'chrome.exe': ('Google Chrome', 'Web Browser', 'Globe'),
    'msedge.exe': ('Microsoft Edge', 'Web Browser', 'Globe'),
    'firefox.exe': ('Mozilla Firefox', 'Web Browser', 'Globe'),
    'brave.exe': ('Brave Browser', 'Web Browser', 'Globe'),
    'opera.exe': ('Opera Browser', 'Web Browser', 'Globe'),
    'opera_gx.exe': ('Opera GX Gaming Browser', 'Web Browser', 'Globe'),
    'vivaldi.exe': ('Vivaldi Browser', 'Web Browser', 'Globe'),
    'arc.exe': ('Arc Browser', 'Web Browser', 'Globe'),
    'tor.exe': ('Tor Browser', 'Web Browser', 'Globe'),
    'safari.exe': ('Apple Safari', 'Web Browser', 'Globe'),
}

# Comprehensive Known Interactive Applications Catalog
APP_CATALOG: Dict[str, Tuple[str, str, str]] = {
    # Messaging & Social
    'whatsapp.exe': ('WhatsApp Desktop', 'Messaging & Chat', 'MessageSquare'),
    'whatsapp.root.exe': ('WhatsApp Desktop', 'Messaging & Chat', 'MessageSquare'),
    'telegram.exe': ('Telegram Desktop', 'Messaging & Chat', 'Send'),
    'discord.exe': ('Discord', 'Voice & Community', 'Headphones'),
    'slack.exe': ('Slack', 'Messaging & Collaboration', 'MessageSquare'),
    'ms-teams.exe': ('Microsoft Teams', 'Collaboration & Meetings', 'Video'),
    'teams.exe': ('Microsoft Teams', 'Collaboration & Meetings', 'Video'),
    'linkedin.exe': ('LinkedIn Desktop', 'Social & Professional', 'Share2'),
    'zoom.exe': ('Zoom Meetings', 'Video Conferencing', 'Video'),
    'skype.exe': ('Skype', 'Voice & Video', 'PhoneCall'),

    # AI & Productivity
    'chatgpt classic.exe': ('ChatGPT Desktop', 'AI & Productivity', 'Sparkles'),
    'chatgpt.exe': ('ChatGPT Desktop', 'AI & Productivity', 'Sparkles'),
    'mscopilot.exe': ('Microsoft Copilot', 'AI & Productivity', 'Sparkles'),
    'copilot.exe': ('Microsoft Copilot', 'AI & Productivity', 'Sparkles'),
    'claude.exe': ('Claude Desktop', 'AI & Productivity', 'Sparkles'),
    'notion.exe': ('Notion Workspace', 'Productivity & Notes', 'FileText'),
    'obsidian.exe': ('Obsidian Vault', 'Knowledge Base', 'BookOpen'),
    'onenote.exe': ('Microsoft OneNote', 'Notebook & Notes', 'Edit'),

    # Development & Engineering
    'antigravity.exe': ('Antigravity IDE', 'AI Development Tool', 'Terminal'),
    'code.exe': ('Visual Studio Code', 'Development Environment', 'Code'),
    'devenv.exe': ('Visual Studio', 'Development Environment', 'Code'),
    'pycharm64.exe': ('PyCharm IDE', 'Python Development', 'Terminal'),
    'idea64.exe': ('IntelliJ IDEA', 'Development Environment', 'Terminal'),
    'clion64.exe': ('CLion IDE', 'C/C++ Development', 'Terminal'),
    'webstorm64.exe': ('WebStorm IDE', 'Web Development', 'Code'),
    'sublime_text.exe': ('Sublime Text', 'Text & Code Editor', 'FileCode'),
    'postman.exe': ('Postman', 'API Development Tool', 'Send'),
    'dbeaver.exe': ('DBeaver', 'Database Management', 'Database'),
    'git-bash.exe': ('Git Bash', 'Terminal Console', 'Terminal'),
    'windowsterminal.exe': ('Windows Terminal', 'Modern Terminal', 'Terminal'),
    'powershell.exe': ('PowerShell', 'PowerShell Console', 'Terminal'),
    'cmd.exe': ('Command Prompt', 'Command Line', 'Terminal'),

    # Office & Documents
    'winword.exe': ('Microsoft Word', 'Office Document', 'FileText'),
    'excel.exe': ('Microsoft Excel', 'Spreadsheet Analytics', 'Table'),
    'powerpnt.exe': ('Microsoft PowerPoint', 'Slide Presentation', 'Presentation'),
    'outlook.exe': ('Microsoft Outlook', 'Email & Calendar', 'Mail'),
    'acrobat.exe': ('Adobe Acrobat Reader', 'PDF Document Viewer', 'File'),
    'foxitreader.exe': ('Foxit PDF Reader', 'PDF Document Viewer', 'File'),

    # Media & Creative
    'spotify.exe': ('Spotify', 'Media & Music', 'Music'),
    'vlc.exe': ('VLC Media Player', 'Media Player', 'Play'),
    'steam.exe': ('Steam Gaming Client', 'Gaming Platform', 'Gamepad'),
    'figma.exe': ('Figma', 'Design & Prototyping', 'Layout'),
    'photoshop.exe': ('Adobe Photoshop', 'Graphic Design', 'Image'),

    # System & Utilities
    'notepad.exe': ('Notepad', 'Text Editor', 'FileText'),
    'notepad++.exe': ('Notepad++', 'Enhanced Text Editor', 'FileText'),
    'calc.exe': ('Calculator', 'Utility', 'Calculator'),
    'calculatorapp.exe': ('Calculator', 'Utility', 'Calculator'),
    'snippingtool.exe': ('Snipping Tool', 'Screen Capture', 'Camera'),
    'explorer.exe': ('Windows File Explorer', 'System Navigation', 'Folder'),
    'taskmgr.exe': ('Windows Task Manager', 'System Monitor', 'Activity'),
    'wps.exe': ('WPS Office', 'Office Document', 'FileText'),
}

# Background system services, drivers, and noise to suppress
SYSTEM_NOISE: set = {
    'svchost.exe', 'conhost.exe', 'runtimebroker.exe', 'taskhostw.exe', 'system',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
    'fontdrvhost.exe', 'dwm.exe', 'memory compression', 'registry', 'spoolsv.exe',
    'searchindexer.exe', 'tiworker.exe', 'trustedinstaller.exe', 'audiodg.exe',
    'wmiprvse.exe', 'compattelrunner.exe', 'sc.exe', 'tasklist.exe', 'netstat.exe',
    'idle_report.exe', 'filecoauth.exe', 'dllhost.exe', 'expressconnect.exe',
    'softlandingtask.exe', 'shellhost.exe', 'sdbinst.exe', 'wsqmcons.exe', 'wermgr.exe',
    'devicecensus.exe', 'usoclient.exe', 'mousocoreworker.exe', 'sedlauncher.exe',
    'gamingservices.exe', 'ctfmon.exe', 'smartscreen.exe',
    'comppkgsrv.exe', 'identity_helper.exe', 'searchfilterhost.exe', 'searchprotocolhost.exe',
    'backgroundtaskhost.exe', 'sihost.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe',
    'startmenuexperiencehost.exe', 'textinputhost.exe', 'shellexperiencehost.exe', 'searchhost.exe',
    'rg_embedded', 'language_server.exe', 'sgrmbroker.exe', 'dashost.exe', 'wlanext.exe',
    'ibtsiva.exe', 'intelremotemanagement.exe', 'atieclxx.exe', 'apmsgfwd.exe', 'apremote.exe',
    'apntex.exe', 'apoint.exe', 'appactions.exe', 'applicationframehost.exe', 'crossdeviceresume.exe',
    'dpm.exe', 'dpmcrashhandler.exe', 'dell.techhub.instrumentation.userprocess.exe', 'hidfind.exe',
    'igfxem.exe', 'jusched.exe', 'microsoftstartfeedprovider.exe', 'onedrive.sync.service.exe',
    'onedrive.exe', 'rtkauduservice64.exe', 'sdxhelper.exe', 'wavessvc64.exe', 'webcompanion.exe',
    'widgetboard.exe', 'widgetservice.exe', 'brightdata.exe', 'pixelsee.exe', 'pixelsee_crashpad_handler.exe',
    'unsecapp.exe', 'python.exe', 'net_updater64.exe', 'etdctrl.exe', 'defendersessionhelper.exe',
    'crossdeviceservice.exe', 'syntpenh.exe', 'hola.exe', 'wpscloudsvr.exe', 'promecefpluginhost.exe',
    'amdrsserv.exe', 'amdow.exe', 'amdrssrcext.exe', 'jucheck.exe', 'm365copilot.exe',
    'useroobebroker.exe', 'cncmd.exe', 'codex.exe', 'codex-computer-use-swift.exe', 'radeonsoftware.exe',
    'm365copilot_autostarter.exe', 'adobecollabsync.exe', 'bridgecommunication.exe', 'systemsettings.exe',
    'phoneexperiencehost.exe', 'windowspackagemanagerserver.exe', 'adobearm.exe', 'adnotificationmanager.exe',
    'helper.exe', 'crashhelper.exe', 'snippingtool.exe'
}


def get_active_user_applications() -> List[Dict[str, Any]]:
    """
    Scans the operating system in real-time and extracts all currently running
    interactive user applications and web browsers.
    """
    if os.name != "nt":
        return []

    try:
        out = subprocess.check_output(
            ['tasklist', '/FO', 'CSV'],
            text=True,
            errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
    except Exception:
        return []

    reader = csv.reader(io.StringIO(out))
    _ = next(reader, None)

    active_apps: Dict[str, Dict[str, Any]] = {}

    for row in reader:
        if not row or len(row) < 4:
            continue
        exe = row[0].strip()
        pid = row[1].strip()
        session_num = row[3].strip()
        mem = row[4].strip() if len(row) > 4 else ""

        # Only process user sessions (session_num != '0')
        if session_num == '0':
            continue

        exe_lower = exe.lower()
        if exe_lower in SYSTEM_NOISE or 'crashpad' in exe_lower:
            continue

        # Skip generic webview sub-processes unless WhatsApp
        if exe_lower == 'msedgewebview2.exe':
            continue

        if exe_lower in active_apps:
            active_apps[exe_lower]['instances'] += 1
            continue

        if exe_lower in BROWSERS:
            name, cat, icon = BROWSERS[exe_lower]
        elif exe_lower in APP_CATALOG:
            name, cat, icon = APP_CATALOG[exe_lower]
        else:
            base = os.path.splitext(exe)[0]
            name = base.replace('_', ' ').replace('-', ' ').title()
            cat = 'Application'
            icon = 'App'

        active_apps[exe_lower] = {
            'executable': exe,
            'app_name': name,
            'category': cat,
            'icon': icon,
            'instances': 1,
            'memory': mem,
            'status': 'Active'
        }

    return list(active_apps.values())


def resolve_process_display(image_path: str, command_line: str = "") -> Tuple[str, str, str]:
    """
    Given a process image path and command line, returns:
    (display_name, friendly_command, category)
    """
    if not image_path:
        return "Unknown Application", command_line or "", "Application"

    base_exe = image_path.split("\\")[-1].lower()
    cmd_lower = (command_line or "").lower()

    # 1. Web Browsers & Tabs
    if base_exe in BROWSERS:
        browser_name, cat, _ = BROWSERS[base_exe]
        if "--type=renderer" in cmd_lower:
            return f"{browser_name} (Web Tab)", f"{browser_name} - Active Web Tab Navigation", "Web Browser"
        return browser_name, f"{browser_name} Web Browser Launched", "Web Browser"

    # 2. WhatsApp Desktop
    if base_exe in ['whatsapp.exe', 'whatsapp.root.exe']:
        return "WhatsApp Desktop", "WhatsApp Desktop - Active Messaging Application", "Messaging & Chat"

    # 3. Antigravity IDE
    if 'antigravity.exe' in base_exe or ('antigravity' in base_exe and 'language_server' not in base_exe):
        return "Antigravity IDE", "Google DeepMind Antigravity AI IDE", "Development Tool"

    # 4. Known Applications Catalog
    if base_exe in APP_CATALOG:
        app_name, cat, _ = APP_CATALOG[base_exe]
        return app_name, f"{app_name} Application Active", cat

    # 5. General Application Fallback
    clean_name = os.path.splitext(base_exe)[0].replace('_', ' ').replace('-', ' ').title()
    return clean_name, command_line or f"{clean_name} Application Executed", "Application"
