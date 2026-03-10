"""Check if cerf.exe is running and responsive."""
import subprocess, sys, time

def check():
    # Check if running
    r = subprocess.run(['tasklist', '/fi', 'imagename eq cerf.exe', '/fo', 'csv', '/nh'],
                       capture_output=True, text=True)
    if 'cerf.exe' not in r.stdout:
        print("CERF: NOT RUNNING")
        return False

    # Check if responsive by trying to enumerate windows with a timeout
    try:
        import ctypes
        u32 = ctypes.windll.user32

        # Use a simple IsHungAppWindow check on known cerf windows
        found_any = False
        hung = False

        def enum_callback(hwnd, lparam):
            nonlocal found_any, hung
            pid = ctypes.c_ulong()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            # Get cerf PID
            if u32.IsWindow(hwnd) and u32.IsWindowVisible(hwnd):
                if u32.IsHungAppWindow(hwnd):
                    found_any = True
                    hung = True
                else:
                    found_any = True
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.LPARAM)
        u32.EnumWindows(WNDENUMPROC(enum_callback), 0)

        # More reliable: check via interact.py windows command with timeout
        r2 = subprocess.run([sys.executable, 'Z:/tools/interact.py', 'windows'],
                           capture_output=True, text=True, timeout=5)
        if 'is NOT running' in r2.stdout:
            print("CERF: NOT RUNNING")
            return False
        if r2.returncode != 0:
            print("CERF: HUNG (interact.py failed)")
            return False
        print("CERF: RUNNING OK")
        # Print brief window summary
        for line in r2.stdout.split('\n')[:5]:
            if line.strip():
                print(f"  {line.strip()}")
        return True
    except subprocess.TimeoutExpired:
        print("CERF: HUNG (timeout)")
        return False
    except Exception as e:
        print(f"CERF: CHECK FAILED ({e})")
        return False

if __name__ == '__main__':
    check()
