import socket
import threading
import datetime
import json
import time
import os
import sys
import subprocess
import ctypes
import hashlib
import base64

# --- GUI and External Dependencies Setup ---

HAS_GUI = False
HAS_CLIPBOARD = False
HAS_CRYPTO = False

def install_dependencies():
    required_packages = ['pystray', 'Pillow', 'pyperclip', 'cryptography'] 
    log_file = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "server_install_log.txt")
    try:
        if sys.stdout: print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Installing dependencies...")
        
        with open(log_file, "a") as f:
            f.write(f"[{datetime.datetime.now()}] Attempting to install libraries...\n")
        
        pip_executable = [sys.executable, "-m", "pip", "install"]
        process = subprocess.run(
            pip_executable + required_packages, check=True, capture_output=True, text=True
        )
        return True
    except Exception as e:
        with open(log_file, "a") as f:
            f.write(f"[{datetime.datetime.now()}] ERROR installing dependencies: {e}\n")
        return False

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

# --- Configuration Loading ---

SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0])) 
CONFIG_FILE = os.path.join(SCRIPT_DIR, "serverconfig.json")
IP_STORAGE_FILE = os.path.join(SCRIPT_DIR, "friend_ips.json")

DEFAULT_CONFIG = {
    "HOST": "0.0.0.0",
    "SYNC_PORT": "",
    "MAX_CONNECTIONS": 5,
    "BROADCAST_PORT": "",
    "GROUP_KEY": "",
    "DEBUG_MODE": False
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            
            print("Configuration file created.")
            print(f"Please edit {CONFIG_FILE} and set GROUP_KEY, SYNC_PORT, and BROADCAST_PORT.")
            if os.name == 'nt':
                 ctypes.windll.user32.MessageBoxW(0, f"Config created at {CONFIG_FILE}.\nPlease set keys and ports.", "Config Required", 0x40)
            sys.exit(0)
        except Exception:
            sys.exit(1)
            
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            return config
    except Exception:
        sys.exit(1)

def save_config(new_config):
    """Saves the configuration dictionary back to the JSON file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(new_config, f, indent=4)
    except Exception as e:
        print(f"Error saving config: {e}")

config = load_config()

# Retrieve raw values
HOST = config.get("HOST", "0.0.0.0")
_SYNC_PORT_RAW = config.get("SYNC_PORT", "")
_BROADCAST_PORT_RAW = config.get("BROADCAST_PORT", "")
GROUP_KEY = config.get("GROUP_KEY", "")
MAX_CONNECTIONS = config.get("MAX_CONNECTIONS", 5)
DEBUG_MODE = config.get("DEBUG_MODE", False)

# --- Validation ---
missing_fields = []
if not GROUP_KEY:
    missing_fields.append("GROUP_KEY")
if not _SYNC_PORT_RAW:
    missing_fields.append("SYNC_PORT")
if not _BROADCAST_PORT_RAW:
    missing_fields.append("BROADCAST_PORT")

if missing_fields:
    err_msg = "CRITICAL ERROR: The following config values are missing:\n" + "\n".join([f"- {m}" for m in missing_fields])
    print(err_msg)
    
    if os.name == 'nt':
         ctypes.windll.user32.MessageBoxW(0, err_msg, "Config Error", 0x10)
    sys.exit(1)

if not HAS_CRYPTO:
    print("CRITICAL ERROR: Cryptography library missing.")
    sys.exit(1)

# --- Post-Validation Conversion ---
try:
    SYNC_PORT = int(_SYNC_PORT_RAW)
    BROADCAST_PORT = int(_BROADCAST_PORT_RAW)
except ValueError:
    print("CRITICAL ERROR: SYNC_PORT and BROADCAST_PORT must be numbers.")
    sys.exit(1)

# --- Encryption Helper ---
def get_cipher_suite(key_str):
    key_bytes = hashlib.sha256(key_str.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)

CIPHER = get_cipher_suite(GROUP_KEY)

FRIEND_IPS = {} 
ip_lock = threading.Lock()
LAST_HANDSHAKE_TIME = "Never" 
LAST_HANDSHAKE_ID = "None"    

# Global event to signal threads to stop
SHUTDOWN_EVENT = threading.Event()

# --- Console Allocation Logic ---
if DEBUG_MODE and os.name == 'nt':
    try:
        ctypes.windll.kernel32.AllocConsole()
        sys.stdout = open('CONOUT$', 'w')
        sys.stderr = open('CONOUT$', 'w')
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] *** DEBUG MODE ENABLED ***")
    except Exception as e:
        pass

# --- GUI Helper Functions ---

def create_icon_image():
    img = Image.new('RGB', (64, 64), color='white')
    d = ImageDraw.Draw(img)
    d.rectangle([16, 16, 48, 48], fill='blue') 
    return img

def remove_friend_handler(friend_id):
    """Handler to remove a friend from the DB when clicked."""
    def handler(icon, item):
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] GUI: Removing {friend_id} from database...")
        with ip_lock:
            if friend_id in FRIEND_IPS:
                del FRIEND_IPS[friend_id]
        
        # Save to disk
        save_ips(icon)
        
        if icon.HAS_NOTIFICATION:
            icon.notify(f"Removed {friend_id} from database.", title="Entry Deleted")
            
    return handler

def exit_action(icon, item):
    """Action to close the server gracefully."""
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Server shutting down by user request.")
    SHUTDOWN_EVENT.set() 
    icon.stop() 

def restart_debug_action(icon, item):
    """Toggles Debug Mode in config and restarts the application."""
    new_mode = not DEBUG_MODE
    config["DEBUG_MODE"] = new_mode
    save_config(config)
    
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Toggling Debug Mode to {new_mode} and restarting...")
    
    SHUTDOWN_EVENT.set()
    icon.stop()
    
    # Restart the executable
    try:
        time.sleep(1) 
        subprocess.Popen([sys.executable] + sys.argv)
    except Exception as e:
        print(f"Failed to restart: {e}")

def update_handshake_time(icon=None, friend_id=None):
    """Updates the global timestamp and ID, then refreshes the GUI."""
    global LAST_HANDSHAKE_TIME, LAST_HANDSHAKE_ID
    LAST_HANDSHAKE_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if friend_id:
        LAST_HANDSHAKE_ID = friend_id
        
    if icon:
        update_icon_tooltip(icon)
        icon.menu = pystray.Menu(*create_menu_items())

def create_menu_items(): 
    items = []
    
    # Show Last Handshake Time AND ID in the menu
    display_str = f"Last Handshake: {LAST_HANDSHAKE_TIME}"
    if LAST_HANDSHAKE_ID != "None":
        display_str += f" ({LAST_HANDSHAKE_ID})"
        
    items.append(pystray.MenuItem(display_str, None, enabled=False))
    items.append(pystray.MenuItem(" ", None, enabled=False)) 

    if FRIEND_IPS:
        items.append(pystray.MenuItem("--- Friends (Click to REMOVE) ---", None, enabled=False))
        with ip_lock:
            safe_items = list(FRIEND_IPS.items())
            
        for friend, data in safe_items:
            ip_addr = data.get('ip', 'N/A')
            items.append(pystray.MenuItem(f"{friend}: {ip_addr}", remove_friend_handler(friend)))
        items.append(pystray.MenuItem(" ", None, enabled=False)) 
    else:
        items.append(pystray.MenuItem("No Friends Connected Yet", None, enabled=False))
        
    debug_label = "Restart in Normal Mode" if DEBUG_MODE else "Restart in Debug Mode"
    items.append(pystray.MenuItem(debug_label, restart_debug_action))
    
    items.append(pystray.MenuItem("Exit DinoSync Server", exit_action))
    return items

def update_icon_tooltip(icon):
    count = len(FRIEND_IPS)
    icon.title = f"DinoSync Server | Friends: {count} | Last: {LAST_HANDSHAKE_TIME}"
    icon.menu = pystray.Menu(*create_menu_items())

# --- Persistence Functions ---

def load_ips(icon=None):
    global FRIEND_IPS
    try:
        with open(IP_STORAGE_FILE, 'r') as f:
            FRIEND_IPS = json.load(f)
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Loaded {len(FRIEND_IPS)} IPs from database.")
        if icon:
            update_icon_tooltip(icon)
    except FileNotFoundError:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] No database found. Starting fresh.")
    except Exception as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error loading database: {e}")

def save_ips(icon=None):
    with ip_lock:
        try:
            with open(IP_STORAGE_FILE, 'w') as f:
                json.dump(FRIEND_IPS, f, indent=4)
        except Exception as e:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error saving database: {e}")
            
    if icon:
        icon.update_menu()
        update_icon_tooltip(icon)

# --- Networking ---

def send_db_to_target(target_ip, target_port):
    """Sends the database to a specific target."""
    with ip_lock:
        master_db_json = json.dumps(FRIEND_IPS)
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(5)
        sock.connect((target_ip, target_port)) 
        
        # Encrypt Payload
        encrypted_db = CIPHER.encrypt(master_db_json.encode('utf-8'))
        sock.sendall(encrypted_db)
        
        # Wait for Client ACK
        sock.recv(1024)
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] >> Database pushed to {target_ip}:{target_port}")
        
    except socket.error as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] !! ERROR pushing DB to {target_ip}:{target_port} - {e}")
    except Exception as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] !! General Error pushing DB: {e}")
    finally:
        sock.close()

def broadcast_update(exclude_friend_id=None):
    """Pushes database to ALL clients."""
    with ip_lock:
        items = list(FRIEND_IPS.items())
        
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Broadcasting update to {len(items)} clients...")
    for friend_id, data in items:
        target_ip = data.get('ip')
        target_port = data.get('port')
        if target_ip and target_port:
             threading.Thread(target=send_db_to_target, args=(target_ip, target_port)).start()

def handle_client(conn, addr, icon=None):
    client_ip, client_port = addr
    try:
        data = conn.recv(1024)
        if not data: return
        
        # Decrypt incoming message
        try:
            decrypted_data = CIPHER.decrypt(data)
            message = decrypted_data.decode('utf-8').strip()
        except Exception:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Decryption failed from {client_ip}")
            return

        if message.startswith("REQUEST_DB"):
            parts = message.split(':')
            if len(parts) == 3:
                _, req_id, req_port_str = parts
                try:
                    req_port = int(req_port_str)
                    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] << Manual DB Request from {req_id} ({client_ip})")
                    
                    ack = CIPHER.encrypt("REQUEST_ACCEPTED".encode('utf-8'))
                    conn.sendall(ack)
                    
                    update_handshake_time(icon, req_id)
                    threading.Thread(target=send_db_to_target, args=(client_ip, req_port)).start()
                except ValueError:
                    pass
            return

        parts = message.split(':')
        if len(parts) == 3:
            friend_id, new_ip, listener_port_str = [p.strip() for p in parts]
            try:
                listener_port = int(listener_port_str)
            except ValueError:
                return

            old_ip = FRIEND_IPS.get(friend_id, {}).get('ip')
            
            with ip_lock:
                FRIEND_IPS[friend_id] = {"ip": new_ip, "port": listener_port}
            
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] << Update received from {friend_id}: {new_ip}")
            
            update_handshake_time(icon, friend_id)
            save_ips(icon)

            # Send Encrypted ACK
            conn.sendall(CIPHER.encrypt("CHECK_IN_OK".encode('utf-8')))
            
            if old_ip != new_ip:
                 print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] IP Change detected for {friend_id} ({old_ip} -> {new_ip}). Broadcasting...")
                 broadcast_thread = threading.Thread(target=broadcast_update, args=(friend_id,))
                 broadcast_thread.daemon = True
                 broadcast_thread.start()
            else:
                 print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] IP unchanged for {friend_id}. Pushing DB to sender only.")
                 push_thread = threading.Thread(target=send_db_to_target, args=(client_ip, listener_port))
                 push_thread.daemon = True
                 push_thread.start()

    except Exception as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Handler Error: {e}")
    finally:
        conn.close()

def start_server(icon=None):
    load_ips(icon)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_socket.settimeout(1.0) 
    
    try:
        server_socket.bind((HOST, SYNC_PORT))
        server_socket.listen(MAX_CONNECTIONS)
        
        print("**************************************************")
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DinoSync Server Started")
        print(f"Listening on Port: {SYNC_PORT}")
        print("**************************************************")
        
        while not SHUTDOWN_EVENT.is_set():
            try:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr, icon))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Accept Error: {e}")
                
    except Exception as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Server Socket Error: {e}")
    finally:
        print("Closing server socket...")
        server_socket.close()

if __name__ == "__main__":
    if HAS_GUI:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Starting Server with GUI...")
        ICON_IMAGE = create_icon_image()
        icon = pystray.Icon('ip_sync_server', ICON_IMAGE, title='DinoSync Server', menu=pystray.Menu(*create_menu_items()))
        
        server_thread = threading.Thread(target=start_server, args=(icon,))
        server_thread.daemon = True
        server_thread.start()
        
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] GUI Loop Running. Check System Tray.")
        icon.run() 
        
        print("GUI loop finished. Setting shutdown event.")
        SHUTDOWN_EVENT.set()
        
        print("Waiting for server thread to close resources...")
        server_thread.join()
        
        print("Exiting.")
        sys.exit(0)
    else:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] GUI libraries not found. Running in Console Mode.")
        start_server()