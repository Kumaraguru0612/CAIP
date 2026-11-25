import os
import sys
import subprocess
import time
import signal
import webbrowser

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def ensure_frontend_build(frontend_dir: str):
    dist_index = os.path.join(frontend_dir, "dist", "index.html")
    if not os.path.exists(dist_index):
        print("[*] Production frontend build not found. Building with Vite...")
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        try:
            subprocess.run([npm_cmd, "run", "build"], cwd=frontend_dir, check=True)
            print("[+] Frontend build completed successfully.")
        except Exception as e:
            print(f"[!] Warning: Failed to build frontend automatically: {e}")

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")

    port = os.environ.get("CAIP_PORT", os.environ.get("PORT", "8000"))

    print("=" * 68)
    print("      [*] STARTING CAIP UNIFIED LIVE PLATFORM")
    print("=" * 68)
    print(f"[*] Root Directory:      {root_dir}")
    print(f"[*] Unified Server Port: {port}")
    print("=" * 68)

    # Ensure frontend distribution is ready
    ensure_frontend_build(frontend_dir)

    unified_url = f"http://localhost:{port}"

    print("\n" + "=" * 68)
    print("  [+] ALL 3 PLATFORM COMPONENTS COMBINED INTO ONE LOCALHOST LINK:")
    print("=" * 68)
    print(f"  👉 Primary Unified Link:   {unified_url}")
    print(f"     • SOC Dashboard:        {unified_url}/")
    print(f"     • Interactive API Docs: {unified_url}/docs")
    print(f"     • 5-Step Live Demo Sim: {unified_url}/simulator")
    if os.name == "nt":
        try:
            sys.path.insert(0, backend_dir)
            from app.ingestion.sysmon_service import get_windows_service_status
            svc = get_windows_service_status()
            if svc.get("running"):
                print(f"     • Windows Sysmon Stream: CONNECTED ({svc.get('service_name')} - Live Channel)")
            else:
                print(f"     • Windows Sysmon:        Service {svc.get('state', 'STOPPED')}")
        except Exception:
            pass
    print("=" * 68)

    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        str(port)
    ]

    processes = []
    try:
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=backend_dir
        )
        processes.append(backend_proc)

        print(f"\n[+] Live server active at {unified_url}")
        print("[!] Press Ctrl+C at any time to stop the server.\n")

        # Give server a moment to spin up and open default browser
        time.sleep(1.5)
        try:
            webbrowser.open(unified_url)
        except Exception:
            pass

        while True:
            for p in processes:
                if p.poll() is not None:
                    print(f"\n[!] Server process exited with code {p.returncode}. Shutting down...")
                    return
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping CAIP server...")
    finally:
        for p in processes:
            if p.poll() is None:
                try:
                    if os.name == "nt":
                        subprocess.call(['taskkill', '/F', '/T', '/PID', str(p.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        p.terminate()
                except Exception:
                    pass
        print("[+] All services stopped cleanly.")

if __name__ == "__main__":
    main()
