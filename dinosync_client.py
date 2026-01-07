import socket
import time
import datetime
import json
import os 
import threading
import sys
import platform
import urllib.request
import subprocess
import ctypes
import hashlib
import base64

# --- GUI and External Dependencies Setup ---

HAS_GUI = False
HAS_CLIPBOARD = False
USE_REQUESTS = False 
HAS_CRYPTO = False

def install_dependencies():
    """Attempts to install required Python packages using pip."""
    required_packages = ['pystray', 'Pillow', 'pyperclip', 'cryptography'] 
    
    log_file = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "install_log.txt")
    
    try:
        with open(log_file, "a") as f:
            f.write(f"[{datetime.datetime.now()}] Attempting to install libraries...\n")
        
        pip_executable = [sys.executable, "-m", "pip", "install"]
        process = subprocess.run(
            pip_executable + required_packages,
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except Exception as e:
        with open(log_file, "a") as f:
            f.write(f"[{datetime.datetime.now()}] ERROR installing dependencies: {e}\n")
        return False

# Try importing dependencies
try:
    import pystray
    from PIL import Image, ImageDraw
    import pyperclip
    from cryptography.fernet import Fernet
    HAS_GUI = True
    HAS_CLIPBOARD = True
    HAS_CRYPTO = True
except ImportError:
    if install_dependencies():
        try:
            import pystray
            from PIL import Image, ImageDraw
            import pyperclip
            from cryptography.fernet import Fernet
            HAS_GUI = True
            HAS_CLIPBOARD = True
            HAS_CRYPTO = True
        except ImportError:
            pass

try:
    import requests
    USE_REQUESTS = True
except ImportError:
    pass

# --- Helper: Windows Popup ---
def show_message_box(title, message, is_error=False):
    """Shows a native Windows message box since we have no console."""
    if os.name == 'nt':
        style = 0x10 if is_error else 0x40 
        ctypes.windll.user32.MessageBoxW(0, message, title, style)
    else:
        print(f"[{title}] {message}")

if not HAS_CRYPTO:
    show_message_box("Critical Error", "Cryptography library failed to install. Cannot run securely.", is_error=True)
    sys.exit(1)

# --- Configuration Loading ---

SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0])) 
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
LOCAL_IP_STORAGE_FILE = os.path.join(SCRIPT_DIR, "local_friend_ips.json")

DEFAULT_CONFIG = {
    "FRIEND_ID": "",
    "GROUP_KEY": "",
    "SYNC_HOST": "",
    "SYNC_PORT": "",
    "BROADCAST_PORT": "",
    "LISTENER_HOST": "0.0.0.0",
    "AUTO_SYNC_TIME": "12:00",
    "MUTE_NOTIFICATIONS": True
}

def load_config():
    """Loads configuration from config.json, creating it if necessary."""
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            
            show_message_box(
                "Configuration Required",
                f"A default config.json file has been created at:\n{CONFIG_FILE}\n\nPlease open this file and fill in all required fields (FRIEND_ID, GROUP_KEY, SYNC_HOST, PORTS).",
                is_error=False
            )
            sys.exit(0)
        except Exception as e:
            show_message_box("Critical Error", f"Could not create config file: {e}", is_error=True)
            sys.exit(1)
            
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            return config
    except Exception as e:
        show_message_box("Configuration Error", f"Could not load config.json: {e}", is_error=True)
        sys.exit(1)

# Load values from config
config = load_config()

# Retrieve raw values (might be empty strings)
FRIEND_ID = config.get("FRIEND_ID", "")
GROUP_KEY = config.get("GROUP_KEY", "")
SYNC_HOST = config.get("SYNC_HOST", "")
_SYNC_PORT_RAW = config.get("SYNC_PORT", "")
_BROADCAST_PORT_RAW = config.get("BROADCAST_PORT", "")

# Non-critical defaults
LISTENER_HOST = config.get("LISTENER_HOST", "0.0.0.0")
AUTO_SYNC_TIME = config.get("AUTO_SYNC_TIME", "12:00")
MUTE_NOTIFICATIONS = config.get("MUTE_NOTIFICATIONS", True)

# --- Validation Logic ---
missing_fields = []

if FRIEND_ID == "":
    missing_fields.append("FRIEND_ID")
if not GROUP_KEY:
    missing_fields.append("GROUP_KEY")
if not SYNC_HOST:
    missing_fields.append("SYNC_HOST")
if not _SYNC_PORT_RAW:
    missing_fields.append("SYNC_PORT")
if not _BROADCAST_PORT_RAW:
    missing_fields.append("BROADCAST_PORT")

if missing_fields:
    error_msg = "The following configuration values are missing or invalid:\n\n"
    error_msg += "\n".join(f"- {field}" for field in missing_fields)
    error_msg += "\n\nPlease update config.json and restart."
    
    show_message_box("Configuration Error", error_msg, is_error=True)
    sys.exit(1)

# --- Post-Validation Conversion ---
try:
    SYNC_PORT = int(_SYNC_PORT_RAW)
    BROADCAST_PORT = int(_BROADCAST_PORT_RAW)
except ValueError:
    show_message_box("Configuration Error", "SYNC_PORT and BROADCAST_PORT must be valid numbers.", is_error=True)
    sys.exit(1)

# --- Encryption Helper ---
def get_cipher_suite(key_str):
    # Hash the user key to 32 bytes and base64 encode it for Fernet
    key_bytes = hashlib.sha256(key_str.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)

CIPHER = get_cipher_suite(GROUP_KEY)

WAN_IP_SERVICE_URL = "https://api.ipify.org"
LOCAL_FRIEND_IPS = {}
ICON_IMAGE = None
LAST_HANDSHAKE_TIME = "Never" 
LAST_NOTIFICATION_TIME = 0 

# --- GUI Helper Functions ---

def create_icon_image(color='red'):
    """Creates a simple, recognizable icon with a dynamic color."""
    img = Image.new('RGB', (64, 64), color='white')
    d = ImageDraw.Draw(img)
    # Support for yellow, green, red
    d.rectangle([16, 16, 48, 48], fill=color)
    return img

def update_icon_color(icon, status_color='red'):
    """Updates the icon image based on connection status or color name."""
    # Map status keywords to colors, or accept direct color names
    if status_color == 'success':
        color = 'green'
    elif status_color == 'error':
        color = 'red'
    else:
        color = status_color # e.g. 'yellow'
        
    icon.icon = create_icon_image(color)

def update_handshake_status(icon=None, success=False):
    """Updates timestamp, icon color, and handles notifications."""
    global LAST_HANDSHAKE_TIME, LAST_NOTIFICATION_TIME
    
    if success:
        LAST_HANDSHAKE_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if icon:
            update_icon_color(icon, 'success')
            update_icon_tooltip(icon)
            icon.update_menu()
            
            # Debounce notification
            current_time = time.time()
            if not MUTE_NOTIFICATIONS and icon.HAS_NOTIFICATION:
                if (current_time - LAST_NOTIFICATION_TIME) > 5:
                    icon.notify("Sync successful. Database updated.", title="DinoSync Connected")
                    LAST_NOTIFICATION_TIME = current_time
    else:
        # On failure, revert to red
        if icon:
            update_icon_color(icon, 'error')

def copy_ip_handler(ip_address):
    def handler(icon, item):
        if HAS_CLIPBOARD:
            try:
                pyperclip.copy(ip_address)
                if not MUTE_NOTIFICATIONS and icon.HAS_NOTIFICATION:
                    icon.notify(f"Copied {ip_address} to clipboard.", title="IP Copied!")
            except Exception:
                pass
    return handler

def run_manual_refresh_sequence(icon):
    """Executes the full refresh sequence: Send IP Update -> Request DB."""
    # Manual refresh does NOT retry on fail
    perform_update_check(icon, is_manual=True)
    request_db_sync(icon)

def manual_refresh_action(icon, item):
    """Manually triggers the full refresh sequence in a background thread."""
    if not MUTE_NOTIFICATIONS and icon.HAS_NOTIFICATION:
         icon.notify("Updating IP and refreshing database...", title="Refreshing")
    
    threading.Thread(target=run_manual_refresh_sequence, args=(icon,), daemon=True).start()

def create_menu_items(icon):
    items = []
    
    items.append(pystray.MenuItem(f"Last Sync: {LAST_HANDSHAKE_TIME}", None, enabled=False))
    items.append(pystray.MenuItem(" ", None, enabled=False)) 

    if LOCAL_FRIEND_IPS:
        items.append(pystray.MenuItem("--- Click to Copy IP ---", None, enabled=False))
        for friend, data in LOCAL_FRIEND_IPS.items():
            ip_addr = data.get('ip', 'N/A')
            items.append(pystray.MenuItem(f"{friend}: {ip_addr}", copy_ip_handler(ip_addr)))
        items.append(pystray.MenuItem(" ", None, enabled=False)) 
    else:
        items.append(pystray.MenuItem("IP Database Empty", None, enabled=False))
    
    items.append(pystray.MenuItem("Refresh Now", manual_refresh_action))
    items.append(pystray.MenuItem("Exit DinoSync", exit_action)) 
    return items

def exit_action(icon, item):
    """Gracefully stop the icon loop."""
    icon.stop()

def update_icon_tooltip(icon):
    my_ip = LOCAL_FRIEND_IPS.get(FRIEND_ID, {}).get('ip', 'Unknown')
    status_text = "Connected" if LAST_HANDSHAKE_TIME != "Never" else "Not Connected"
    icon.title = f"DinoSync | {status_text} | My IP: {my_ip}"
    icon.menu = pystray.Menu(lambda: create_menu_items(icon))

# --- Local Persistence Functions ---

def load_local_ips():
    if os.path.exists(LOCAL_IP_STORAGE_FILE):
        try:
            with open(LOCAL_IP_STORAGE_FILE, 'r') as f:
                global LOCAL_FRIEND_IPS
                LOCAL_FRIEND_IPS = json.load(f)
        except Exception:
            pass

def save_local_ips(data_dict, icon=None):
    global LOCAL_FRIEND_IPS
    try:
        LOCAL_FRIEND_IPS = data_dict
        with open(LOCAL_IP_STORAGE_FILE, 'w') as f:
            json.dump(LOCAL_FRIEND_IPS, f, indent=4)
        
        # Saving means we got data successfully -> GREEN STATUS
        update_handshake_status(icon, success=True)
            
    except Exception as e:
        print(f"Error saving IPs: {e}")
        # Save error -> RED STATUS
        update_handshake_status(icon, success=False)

# --- Core Networking Functions ---

def get_wan_ip():
    if USE_REQUESTS:
        try:
            response = requests.get(WAN_IP_SERVICE_URL, timeout=10)
            response.raise_for_status()
            return response.text.strip()
        except Exception:
            return None
    else:
        try:
            req = urllib.request.Request(WAN_IP_SERVICE_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.getcode() == 200:
                    return response.read().decode('utf-8').strip()
        except Exception:
            return None
    return None

def request_db_sync(icon=None):
    try:
        server_ip = socket.gethostbyname(SYNC_HOST)
    except socket.gaierror:
        update_handshake_status(icon, success=False)
        return 

    client_socket = None
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(15) 
        
        client_socket.connect((server_ip, SYNC_PORT))
        
        # Encrypt the request
        payload = f"REQUEST_DB:{FRIEND_ID}:{BROADCAST_PORT}"
        encrypted_message = CIPHER.encrypt(payload.encode('utf-8'))
        client_socket.sendall(encrypted_message)
        
        # Receive Encrypted Response
        encrypted_response = client_socket.recv(4096)
        response = CIPHER.decrypt(encrypted_response).decode('utf-8').strip()
        
        if "REQUEST_ACCEPTED" in response:
            pass
        else:
            update_handshake_status(icon, success=False)
            
    except Exception:
        update_handshake_status(icon, success=False)
    finally:
        if client_socket:
            client_socket.close()

def send_ip_update(ip_address, icon=None, set_error_icon=True):
    """
    Sends IP update to server.
    Returns True if successful, False if failed.
    If set_error_icon is False, it won't turn the icon Red on failure (used for Retry logic).
    """
    try:
        server_ip = socket.gethostbyname(SYNC_HOST)
    except socket.gaierror:
        if not MUTE_NOTIFICATIONS and icon and icon.HAS_NOTIFICATION:
            icon.notify(f"Could not resolve {SYNC_HOST}", title="Connection Error")
        if set_error_icon:
            update_handshake_status(icon, success=False)
        return False

    client_socket = None
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(15) 
        
        client_socket.connect((server_ip, SYNC_PORT))
        
        # Encrypt the update
        payload = f"{FRIEND_ID}:{ip_address}:{BROADCAST_PORT}"
        encrypted_message = CIPHER.encrypt(payload.encode('utf-8'))
        client_socket.sendall(encrypted_message)
        
        # Expect encrypted ACK or data
        client_socket.recv(1024)
        
        # Successful handshake -> GREEN STATUS
        update_handshake_status(icon, success=True)
        return True
            
    except socket.error as e:
        if not MUTE_NOTIFICATIONS and icon and icon.HAS_NOTIFICATION and set_error_icon:
             icon.notify("Could not connect to Sync Server.", title="Connection Failed")
        
        if set_error_icon:
            update_handshake_status(icon, success=False)
        return False
    except Exception:
        if set_error_icon:
            update_handshake_status(icon, success=False)
        return False
    finally:
        if client_socket:
            client_socket.close()

# --- Client Broadcast Listener (Daemon) ---

def handle_incoming_db(conn, addr, icon=None):
    try:
        # Receive large buffer for potentially large JSON DB
        data = conn.recv(8192)
        if not data: return
        
        # Decrypt
        decrypted_data = CIPHER.decrypt(data)
        response_message = decrypted_data.decode('utf-8').strip()
        received_db = json.loads(response_message)
        
        save_local_ips(received_db, icon=icon)
        
        # Send Encrypted ACK
        conn.sendall(CIPHER.encrypt("BROADCAST_ACK".encode('utf-8')))
    except Exception:
        pass
    finally:
        conn.close()

def run_listener_daemon_core(icon=None):
    load_local_ips() 
    if icon:
        update_icon_tooltip(icon)
        update_icon_color(icon, 'red')

    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        listener_socket.bind((LISTENER_HOST, BROADCAST_PORT))
        listener_socket.listen(5)
        
        while True:
            conn, addr = listener_socket.accept()
            handler_thread = threading.Thread(target=handle_incoming_db, args=(conn, addr, icon))
            handler_thread.daemon = True
            handler_thread.start()

    except Exception as e:
        if not MUTE_NOTIFICATIONS and icon and icon.HAS_NOTIFICATION:
            icon.notify(f"Listener Port {BROADCAST_PORT} failed: {e}", title="Daemon Error")
        update_handshake_status(icon, success=False)
    finally:
        if 'listener_socket' in locals():
            listener_socket.close()

# --- Scheduler Logic ---

def perform_update_check(icon=None, is_manual=False):
    current_ip = get_wan_ip()
    
    if not current_ip:
        # If no internet, just go red immediately
        update_handshake_status(icon, success=False)
        return

    # Attempt 1
    # If this is manual, we want standard behavior (Fail = Red). 
    # If auto, we suppress the error icon so we can handle the retry yellow state.
    suppress_error = not is_manual 
    
    success = send_ip_update(current_ip, icon, set_error_icon=(not suppress_error))
    
    if success:
        return # Done, icon is green.
        
    # If we failed and it was automatic, enter Retry Logic
    if not success and not is_manual:
        # Set Yellow
        update_icon_color(icon, 'yellow')
        if not MUTE_NOTIFICATIONS and icon.HAS_NOTIFICATION:
            # Optional: Notify user we are retrying
            pass 
            
        time.sleep(10) # Wait 10 seconds
        
        # Attempt 2 - this time allow error icon (Red) if it fails
        send_ip_update(current_ip, icon, set_error_icon=True)

def run_scheduler_core(icon=None):
    time.sleep(3) 
    
    perform_update_check(icon, is_manual=False)
    
    while True:
        try:
            # Parse configured time
            target_time_obj = datetime.datetime.strptime(AUTO_SYNC_TIME, "%H:%M").time()
        except ValueError:
            target_time_obj = datetime.time(12, 0) # Fallback to noon if parsing fails

        now = datetime.datetime.now()
        target_datetime = datetime.datetime.combine(now.date(), target_time_obj)
        
        # If target time has already passed today, schedule for tomorrow
        if now >= target_datetime:
            target_datetime += datetime.timedelta(days=1)
            
        sleep_seconds = (target_datetime - now).total_seconds()
        
        # Log scheduler (optional debugging)
        # print(f"Sleeping for {sleep_seconds} seconds until {target_datetime}")
        
        time.sleep(sleep_seconds)
        perform_update_check(icon, is_manual=False)

# --- Main Execution Dispatcher ---

if __name__ == "__main__":
    if HAS_GUI:
        # Start Red
        ICON_IMAGE = create_icon_image('red')
        icon = pystray.Icon('ip_sync_client', ICON_IMAGE, title='DinoSync Daemon', menu=pystray.Menu(create_menu_items))
        
        listener_thread = threading.Thread(target=run_listener_daemon_core, args=(icon,))
        listener_thread.daemon = True
        listener_thread.start()
        
        scheduler_thread = threading.Thread(target=run_scheduler_core, args=(icon,))
        scheduler_thread.daemon = True
        scheduler_thread.start()
        
        icon.run() 
        
        sys.exit(0)
    else:
        show_message_box("Dependency Error", "Could not load GUI libraries. Check install_log.txt", is_error=True)