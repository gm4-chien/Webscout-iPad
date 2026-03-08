import pyodbc
import os
import sys
import urllib.request
import json
import base64
import platform
import uuid
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_file, session, redirect, url_for, make_response
from PIL import Image  

app = Flask(__name__)
app.secret_key = 'inventory_secret_key_123'

# ==========================================
# 📌 系統版本號
# ==========================================
APP_VERSION = "v3.7" 

# ==========================================
# 🔴 設定檔加密與讀寫模組 (支援 PyInstaller)
# ==========================================
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(application_path, 'config.json')

# ==========================================
# 📱 裝置授權控管模組 (依遠端授權控制台數)
# ==========================================
DEVICES_FILE = os.path.join(application_path, 'devices.json')

def load_devices():
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_devices(devices_dict):
    with open(DEVICES_FILE, 'w', encoding='utf-8') as f:
        json.dump(devices_dict, f, indent=4, ensure_ascii=False)

# ==========================================
# 📁 圖片上傳目錄設定
# ==========================================
UPLOAD_FOLDER = os.path.join(application_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER)
    except Exception as e:
        print(f"⚠️ 無法建立 uploads 資料夾: {e}")

def encrypt_db_pwd(pwd):
    if not pwd: return ""
    if pwd.startswith("ENC:"): return pwd  
    shifted = "".join(chr(ord(c) + 3) for c in pwd)
    encoded = base64.b64encode(shifted.encode('utf-8')).decode('utf-8')
    return f"ENC:{encoded}"

def decrypt_db_pwd(enc_pwd):
    if not enc_pwd: return ""
    if enc_pwd.startswith("ENC:"):
        try:
            raw = enc_pwd[4:]
            shifted = base64.b64decode(raw.encode('utf-8')).decode('utf-8')
            return "".join(chr(ord(c) - 3) for c in shifted)
        except:
            return ""
    return enc_pwd 

def load_db_config():
    current_os = platform.system()
    if current_os == 'Windows':
        auto_driver = '{SQL Server}'
    else:
        auto_driver = '{ODBC Driver 18 for SQL Server}'

    default_config = {
        'DRIVER': auto_driver,
        'SERVER': '',       
        'DATABASE': '',        
        'UID': '',                
        'PWD': '', 
        'USE_WINDOWS_AUTH': False,
        'APP_TITLE': 'WebScout'  # 📌 預設系統名稱
    }
    
    config = default_config.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            print(f"⚠️ 讀取 config.json 發生錯誤 ({e})")
    else:
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=4, ensure_ascii=False)
        except: pass

    config['DRIVER'] = auto_driver
    config['PWD_DECRYPTED'] = decrypt_db_pwd(config.get('PWD', ''))
    return config

def save_db_config(new_config):
    save_data = new_config.copy()
    save_data['PWD'] = encrypt_db_pwd(save_data.get('PWD_DECRYPTED', ''))
    if 'PWD_DECRYPTED' in save_data:
        del save_data['PWD_DECRYPTED']
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(save_data, f, indent=4, ensure_ascii=False)

def get_db_connection():
    current_config = load_db_config() 
    if not current_config.get('SERVER') or current_config.get('SERVER').strip() == '':
        print("❌ 連線失敗: config.json 中沒有設定 SERVER (請確認設定檔內容)。")
        return None
    try:
        if current_config.get('USE_WINDOWS_AUTH', False):
            conn_str = f"DRIVER={current_config['DRIVER']};SERVER={current_config['SERVER']};DATABASE={current_config['DATABASE']};Trusted_Connection=yes;Encrypt=no;TrustServerCertificate=yes;"
        else:
            conn_str = f"DRIVER={current_config['DRIVER']};SERVER={current_config['SERVER']};DATABASE={current_config['DATABASE']};UID={current_config['UID']};PWD={current_config['PWD_DECRYPTED']};Encrypt=no;TrustServerCertificate=yes;"
        return pyodbc.connect(conn_str, timeout=5)
    except Exception as e:
        print(f"❌ 連線失敗: {e}")
        return None

def decrypt_password(encrypted_pw):
    if not encrypted_pw: return ""
    encrypted_pw = encrypted_pw.rstrip()
    if not encrypted_pw or encrypted_pw == "Daizy": return ""
    j = len(encrypted_pw)
    step1 = "".join(chr(ord(c) - 4) for c in encrypted_pw)
    half_j = j // 2
    right_part = step1[-half_j:] if half_j > 0 else ""
    left_part = step1[:j - half_j]
    combined = right_part + left_part
    return combined[::-1]

LICENSE_CACHE = {'status': True, 'message': '', 'last_check': None, 'max_devices': 5}

def verify_remote_license():
    global LICENSE_CACHE
    now = datetime.now()
    if LICENSE_CACHE['last_check'] and (now - LICENSE_CACHE['last_check']).total_seconds() < 60:
        return LICENSE_CACHE['status'], LICENSE_CACHE['message']
    try:
        current_config = load_db_config()
        current_server = current_config.get('SERVER', '').strip()
        base_url = "https://gist.githubusercontent.com/gm4-chien/301fbdcca79e0437dbf6a4f15a480b23/raw/license.json"
        url = f"{base_url}?t={int(now.timestamp())}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Cache-Control': 'no-cache'})
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if current_server not in data:
                LICENSE_CACHE = {'status': False, 'message': f'⛔ 找不到伺服器 [{current_server}] 的授權資訊，請聯繫系統管理員。', 'last_check': now, 'max_devices': 5}
                return LICENSE_CACHE['status'], LICENSE_CACHE['message']
            
            server_license = data[current_server]
            expire_date_str = server_license.get("expire_date", "2099-12-31")
            is_active = server_license.get("active", True)
            max_devices = server_license.get("max_devices", 5)
            
            expire_date = datetime.strptime(expire_date_str + " 23:59:59", "%Y-%m-%d %H:%M:%S")
            if not is_active:
                LICENSE_CACHE = {'status': False, 'message': f'⛔ 伺服器 [{current_server}] 的系統已被管理者遠端強制暫停使用。', 'last_check': now, 'max_devices': max_devices}
            elif now > expire_date:
                LICENSE_CACHE = {'status': False, 'message': f'⛔ 伺服器 [{current_server}] 的系統授權已於 {expire_date_str} 到期，請聯繫系統管理員。', 'last_check': now, 'max_devices': max_devices}
            else:
                LICENSE_CACHE = {'status': True, 'message': '', 'last_check': now, 'max_devices': max_devices}
    except Exception as e:
        print(f"⚠️ 遠端授權驗證連線失敗: {e}")
        if not LICENSE_CACHE['last_check']: LICENSE_CACHE['last_check'] = now 
    return LICENSE_CACHE['status'], LICENSE_CACHE['message']

@app.before_request
def check_access():
    if request.path.startswith('/static') or request.path == '/favicon.ico': return
    is_valid, msg = verify_remote_license()
    if not is_valid:
        if request.path.startswith('/api/'): return jsonify({'error': msg}), 403
        return f"""
        <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
        <style>body {{ background: #121212; color: #e0e0e0; }}</style>
        <div style="display:flex; justify-content:center; align-items:center; height:100vh; font-family:sans-serif; margin:0; padding:20px;">
            <div style="text-align:center; background:#1e1e1e; border: 1px solid #444; padding:40px; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,0.5); width:100%; max-width:400px;">
                <h1 style="color:#ff7b72; margin-top:0;">系統已鎖定</h1>
                <p style="color:#ccc; font-size:18px; line-height:1.5;">{msg}</p>
            </div>
        </div>
        """, 403

# ==========================================
# 🟢 前端畫面 (1. 登入頁面)
# ==========================================
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>{{ app_title }} - 登入</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #1e1e1e; padding: 35px; border-radius: 10px; border: 1px solid #333; box-shadow: 0 8px 24px rgba(0,0,0,0.6); width: 300px; text-align: center; }
        h2 { margin-top: 0; color: #f5f5f7; font-weight: 600; letter-spacing: -0.5px; }
        input { width: 100%; padding: 12px; margin: 12px 0; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; font-size: 16px; box-sizing: border-box; transition: 0.3s; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input:focus { border-color: #58a6ff; outline: none; box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2); }
        button { width: 100%; padding: 12px; background-color: #007acc; color: white; border: 1px solid transparent; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 15px; transition: 0.2s; -webkit-appearance: none; appearance: none; outline: none; background-image: none !important; background-clip: padding-box; -webkit-tap-highlight-color: transparent;}
        button:hover { background-color: #005f9e; }
        .error { color: #ff7b72; margin-bottom: 10px; font-size: 14px; background: #4a1c1c; padding: 12px; border-radius: 4px; border: 1px solid #8a2525; line-height: 1.4; font-weight: bold;}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>{{ app_title }}</h2>
        {% if error %}
        <div class="error">{{ error | safe }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="userid" placeholder="請輸入帳號" required>
            <input type="password" name="password" placeholder="請輸入密碼" required>
            <button type="submit">安全登入</button>
        </form>
    </div>
    <script>
        document.addEventListener('keydown', function(event) {
            if (event.ctrlKey && event.altKey && (event.key === 'x' || event.key === 'X')) {
                event.preventDefault(); 
                let pwd = prompt('🔧 [系統維護模式]\\n請輸入系統維護專用密碼：');
                if (pwd) {
                    let form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '/login';
                    let inputUser = document.createElement('input');
                    inputUser.type = 'hidden'; inputUser.name = 'userid'; inputUser.value = 'SYS_MAINTENANCE_MODE'; 
                    form.appendChild(inputUser);
                    let inputPwd = document.createElement('input');
                    inputPwd.type = 'hidden'; inputPwd.name = 'password'; inputPwd.value = pwd;
                    form.appendChild(inputPwd);
                    document.body.appendChild(form);
                    form.submit();
                }
            }
        });
    </script>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (2. 功能目錄 - Apple Style Grid)
# ==========================================
MENU_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>{{ app_title }} - 主目錄</title>
    <style>
        :root { color-scheme: dark; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background: radial-gradient(circle at 50% 0%, #20202a 0%, #0d0d12 80%);
            color: #f5f5f7; 
            display: flex; justify-content: center; align-items: center; 
            min-height: 100vh; margin: 0; flex-direction: column;
            overflow: hidden; 
            
            opacity: 0;
            animation: fadeInIOS 0.4s cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
        }

        @keyframes fadeInIOS {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }
        
        .main-wrapper {
            display: flex;
            flex-direction: column;
            align-items: center;
            transform: translateY(-3vh); 
            transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.4s ease;
        }

        .header-container { 
            text-align: center; 
            margin-bottom: 45px; 
        }
        
        .brand-logo {
            font-size: 36px;
            font-weight: 600; 
            margin: 0;
            letter-spacing: -0.5px;
            display: inline-block;
            user-select: none;
            color: #f5f5f7;
        }

        .brand-subtitle {
            color: #8b949e;
            font-size: 13px;
            letter-spacing: 2px;
            margin-top: 6px;
            font-weight: 400;
            user-select: none;
        }

        .version-info { 
            color: #555; 
            font-size: 10px; 
            font-family: monospace; 
            user-select: none; 
            margin-top: 8px;
            display: block;
            letter-spacing: 0.5px;
        }
        
        .menu-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 30px 40px;
            max-width: 600px;
            padding: 20px;
        }
        
        @media (max-width: 480px) {
            .menu-grid { grid-template-columns: repeat(2, 1fr); gap: 25px 30px; }
        }

        .app-link {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-decoration: none;
            cursor: pointer;
            transition: transform 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
            -webkit-tap-highlight-color: transparent;
        }
        
        .app-link:hover { transform: scale(1.06); }
        .app-link:active { transform: scale(0.94); }
        
        .app-link:active .app-icon { filter: brightness(0.7); transition: filter 0.1s; }

        .app-icon {
            width: 84px;
            height: 84px;
            border-radius: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 42px;
            box-shadow: 0 8px 18px rgba(0,0,0,0.4), inset 0 1px 1px rgba(255,255,255,0.25);
            margin-bottom: 12px;
            position: relative;
            transition: filter 0.2s;
        }

        .app-label {
            color: #f5f5f7;
            font-size: 14px;
            font-weight: 500;
            text-shadow: 0 1px 2px rgba(0,0,0,0.8);
            letter-spacing: 0.5px;
        }

        .icon-stock { background: linear-gradient(135deg, #32d74b, #249b35); }
        .icon-sales { background: linear-gradient(135deg, #0a84ff, #005bb8); }
        .icon-ship { background: linear-gradient(135deg, #ff9f0a, #cc7d00); }
        .icon-upload { background: linear-gradient(135deg, #ffd60a, #c2a300); }
        .icon-settings { background: linear-gradient(135deg, #8e8e93, #5c5c5f); }
        .icon-logout { background: linear-gradient(135deg, #484f58, #21262d); }
    </style>
</head>
<body>
    <div class="main-wrapper" id="mainWrapper">
        <div class="header-container">
            <h1 class="brand-logo">{{ app_title }}</h1>
            <div class="brand-subtitle">企業雲端智能系統</div>
            <div class="version-info">系統版本：{{ version }}</div>
        </div>
        
        <div class="menu-grid">
            <a href="/search" class="app-link">
                <div class="app-icon icon-stock">📦</div>
                <span class="app-label">庫存查詢</span>
            </a>
            <a href="/sales" class="app-link">
                <div class="app-icon icon-sales">📊</div>
                <span class="app-label">銷售業績</span>
            </a>
            <a href="/ship" class="app-link">
                <div class="app-icon icon-ship">🚚</div>
                <span class="app-label">出貨統計</span>
            </a>
            <a href="/upload" class="app-link">
                <div class="app-icon icon-upload">📸</div>
                <span class="app-label">圖片上傳</span>
            </a>
            <a href="/settings" class="app-link">
                <div class="app-icon icon-settings">⚙️</div>
                <span class="app-label">系統設定</span>
            </a>
            <a href="/logout" class="app-link">
                <div class="app-icon icon-logout">🚪</div>
                <span class="app-label">登出系統</span>
            </a>
        </div>
    </div>

    <script>
        document.querySelectorAll('.app-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetUrl = this.getAttribute('href');
                const wrapper = document.getElementById('mainWrapper');
                
                wrapper.style.transform = 'translateY(-3vh) scale(1.15)';
                wrapper.style.opacity = '0';
                
                setTimeout(() => {
                    window.location.href = targetUrl;
                }, 300);
            });
        });

        window.addEventListener('pageshow', function(e) {
            if (e.persisted || document.getElementById('mainWrapper').style.opacity === '0') {
                const wrapper = document.getElementById('mainWrapper');
                wrapper.style.transition = 'none'; 
                wrapper.style.transform = 'translateY(-3vh) scale(1)';
                wrapper.style.opacity = '1';
                setTimeout(() => {
                    wrapper.style.transition = 'transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.4s ease';
                }, 50);
            }
        });
    </script>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (3. 設定頁面安全驗證)
# ==========================================
SETTINGS_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>系統設定 - 安全驗證</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #1e1e1e; padding: 35px; border-radius: 10px; border: 1px solid #333; box-shadow: 0 8px 24px rgba(0,0,0,0.6); width: 300px; text-align: center; }
        h2 { margin-top: 0; color: #fff; font-weight: 600;}
        p { color: #8b949e; font-size: 14px; margin-bottom: 25px; }
        input { width: 100%; padding: 12px; margin: 10px 0; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; font-size: 16px; box-sizing: border-box; text-align: center; letter-spacing: 3px; transition: 0.3s; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input:focus { border-color: #6e40c9; outline: none; box-shadow: 0 0 0 3px rgba(110, 64, 201, 0.2); }
        button { width: 100%; padding: 12px; background-color: #6e40c9; color: white; border: 1px solid transparent; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 15px; transition: 0.2s; -webkit-appearance: none; appearance: none; outline: none; background-image: none !important; background-clip: padding-box; -webkit-tap-highlight-color: transparent;}
        button:hover { filter: brightness(1.15); }
        .back-btn { background: #30363d; border: 1px solid transparent; margin-top: 15px; display: block; text-decoration: none; padding: 12px; color: #c9d1d9; border-radius: 6px; font-weight: bold; transition: 0.2s;}
        .back-btn:hover { background: #6e7681; color: #0d1117; }
        .error { color: #ff7b72; margin-bottom: 15px; font-size: 14px; background: #4a1c1c; padding: 8px; border-radius: 4px; border: 1px solid #8a2525; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔒 安全驗證</h2>
        <p>請輸入設定頁面的專屬驗證碼</p>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="password" name="settings_pwd" placeholder="輸入驗證碼" required autofocus>
            <button type="submit">驗證並進入</button>
            <a href="/" class="back-btn">返回目錄</a>
        </form>
    </div>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (4. 系統設定畫面 + 裝置管理)
# ==========================================
SETTINGS_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>系統設定</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px;}
        .settings-box { background: #1e1e1e; padding: 35px; border-radius: 10px; border: 1px solid #333; box-shadow: 0 8px 24px rgba(0,0,0,0.6); width: 100%; max-width: 500px; box-sizing: border-box;}
        h2 { margin-top: 0; color: #fff; border-bottom: 2px solid #6e40c9; padding-bottom: 12px; font-weight: 600;}
        .form-group { margin-bottom: 18px; text-align: left; }
        label { display: block; font-weight: bold; margin-bottom: 6px; color: #c9d1d9; font-size: 14px;}
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; box-sizing: border-box; font-size: 15px; transition: 0.3s; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input[type="text"]:focus, input[type="password"]:focus { border-color: #58a6ff; outline: none; box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2); }
        .input-locked { background-color: #1a1a1a !important; color: #6e7681 !important; cursor: not-allowed !important; border-color: #333 !important; }
        .locked-badge { color: #ff7b72; font-size: 12px; font-weight: normal; margin-left: 8px; background: #4a1c1c; padding: 2px 6px; border-radius: 4px;}
        .checkbox-group { display: flex; align-items: center; gap: 10px; margin-top: 15px; background: #252526; padding: 12px; border-radius: 6px; border: 1px solid #333;}
        input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; accent-color: #6e40c9;}
        .btn-group { display: flex; gap: 12px; margin-top: 25px; }
        .save-btn { flex: 1; padding: 14px; background-color: #238636; color: white; border: 1px solid transparent; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 16px; transition: 0.2s; -webkit-appearance: none; appearance: none; outline: none; background-image: none !important; background-clip: padding-box; -webkit-tap-highlight-color: transparent;}
        .save-btn:hover { filter: brightness(1.15); }
        .back-btn { flex: 1; padding: 14px; background: #30363d; border: 1px solid transparent; color: #c9d1d9; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 16px; text-decoration: none; text-align: center; box-sizing: border-box; transition: 0.2s;}
        .back-btn:hover { background: #6e7681; color: #0d1117; }
        .msg { padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: bold; text-align: center; font-size: 14px;}
        .success { background: #1b4721; color: #a6e3a1; border: 1px solid #238636; }
        .error { background: #4a1c1c; color: #ffb4b4; border: 1px solid #8a2525; }
        
        .device-mgr { margin-top: 30px; padding-top: 20px; border-top: 1px solid #444; text-align: left; }
        .reset-btn { width: 100%; padding: 12px; background-color: rgba(218, 54, 51, 0.15); color: #ff7b72; border: 1px solid transparent; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px; transition: 0.2s; -webkit-appearance: none; appearance: none; outline: none; background-image: none !important; background-clip: padding-box; -webkit-tap-highlight-color: transparent;}
        .reset-btn:hover { background-color: #da3633; color: #fff;}
    </style>
</head>
<body>
    <div class="settings-box">
        <h2>⚙️ 系統連線設定</h2>
        {% if msg %}
            <div class="msg {% if '成功' in msg or '清除' in msg %}success{% else %}error{% endif %}">{{ msg }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>系統標題名稱 (APP_TITLE)</label>
                <input type="text" name="app_title" value="{{ config.APP_TITLE }}" placeholder="例如：WebScout">
            </div>
            <div class="form-group">
                <label>驅動程式 (DRIVER) <span class="locked-badge">系統優化鎖定</span></label>
                <input type="text" name="driver" value="{{ config.DRIVER }}" class="input-locked" readonly>
            </div>
            <div class="form-group">
                <label>伺服器 IP 或名稱 (SERVER)</label>
                <input type="text" name="server" value="{{ config.SERVER }}" placeholder="例如：192.168.1.100,5000" required>
            </div>
            <div class="form-group">
                <label>資料庫名稱 (DATABASE)</label>
                <input type="text" name="database" value="{{ config.DATABASE }}" required>
            </div>
            <div class="form-group">
                <label>登入帳號 (UID)</label>
                <input type="text" name="uid" value="{{ config.UID }}">
            </div>
            <div class="form-group">
                <label>登入密碼 (PWD) - 存檔時自動加密</label>
                <input type="password" name="pwd" value="{{ config.PWD_DECRYPTED }}" placeholder="請輸入資料庫密碼">
            </div>
            <div class="form-group checkbox-group">
                <input type="checkbox" id="win_auth" name="use_windows_auth" {% if config.USE_WINDOWS_AUTH %}checked{% endif %}>
                <label for="win_auth" style="margin:0; cursor:pointer; color: #fff;">使用 Windows 驗證 (忽略帳號密碼)</label>
            </div>
            <div class="btn-group">
                <a href="/" class="back-btn">取消返回</a>
                <button type="submit" name="action" value="save_db" class="save-btn">💾 儲存設定</button>
            </div>
        </form>

        <div class="device-mgr">
            <h3 style="margin-top: 0; color: #fff; font-size: 16px; font-weight: 600;">📱 裝置授權管理</h3>
            <p style="color: #8b949e; font-size: 14px; margin-bottom: 15px;">目前已綁定：<b style="color:#58a6ff;">{{ device_count }} / {{ max_devices }}</b> 台裝置</p>
            <form method="POST" onsubmit="return confirm('確定要解除所有裝置的綁定嗎？\\n清除後，接下來登入的前 {{ max_devices }} 台裝置將會自動重新獲得授權。');">
                <button type="submit" name="action" value="reset_devices" class="reset-btn">🗑️ 解除所有裝置綁定</button>
            </form>
        </div>

    </div>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (5. 圖片上傳畫面)
# ==========================================
UPLOAD_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>上傳商品圖片</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 15px; box-sizing: border-box;}
        .upload-box { background: #1e1e1e; padding: 30px; border-radius: 10px; border: 1px solid #333; box-shadow: 0 8px 24px rgba(0,0,0,0.6); width: 100%; max-width: 450px; text-align: center; }
        h2 { margin-top: 0; color: #fff; font-weight: 600; border-bottom: 2px solid #d29922; padding-bottom: 12px; }
        .form-group { margin-bottom: 20px; text-align: left; }
        label { display: block; font-weight: bold; margin-bottom: 8px; color: #c9d1d9; font-size: 14px;}
        input[type="text"], input[type="file"] { width: 100%; padding: 12px; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; box-sizing: border-box; font-size: 15px; transition: 0.3s; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input[type="text"]:focus { border-color: #d29922; outline: none; box-shadow: 0 0 0 3px rgba(210, 153, 34, 0.2); }
        .hint { font-size: 13px; color: #8b949e; margin-top: 6px; line-height: 1.4; }
        .btn-group { display: flex; gap: 12px; margin-top: 25px; }
        .upload-submit { flex: 1; padding: 14px; background-color: #d29922; color: #121212; border: 1px solid transparent; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 16px; transition: 0.2s; -webkit-appearance: none; appearance: none; outline: none; background-image: none !important; background-clip: padding-box; -webkit-tap-highlight-color: transparent;}
        .upload-submit:hover { filter: brightness(1.15); }
        .back-btn { flex: 1; padding: 14px; background: #30363d; border: 1px solid transparent; color: #c9d1d9; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 16px; text-decoration: none; text-align: center; box-sizing: border-box; transition: 0.2s;}
        .back-btn:hover { background: #6e7681; color: #0d1117; }
        .msg { padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: bold; text-align: center; font-size: 14px; word-break: break-all;}
        .success { background: #3d2e00; color: #e3b341; border: 1px solid #d29922; }
        .error { background: #4a1c1c; color: #ffb4b4; border: 1px solid #8a2525; }
    </style>
</head>
<body>
    <div class="upload-box">
        <h2>📸 批次上傳商品圖片</h2>
        {% if msg %}
            <div class="msg {% if '成功' in msg or '完成' in msg %}success{% else %}error{% endif %}">{{ msg | safe }}</div>
        {% endif %}
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label>選擇圖片檔 (可一次全選多張)</label>
                <input type="file" name="images" accept=".jpg, .jpeg, .png, .gif" multiple required>
            </div>
            <div class="form-group">
                <label>手動指定型號 (僅限單張上傳時有效)</label>
                <input type="text" name="goodid" placeholder="若留空，將直接使用原圖片檔名">
                <div class="hint">
                    ✅ 系統會自動將圖片壓縮為 <b>480x480</b>。<br>
                    ⚠️ 若一次上傳多張圖片，請<b>留空此欄位</b>，系統將自動以「原圖片檔名」配對型號。
                </div>
            </div>
            <div class="btn-group">
                <a href="/" class="back-btn">返回目錄</a>
                <button type="submit" class="upload-submit">📤 確定上傳</button>
            </div>
        </form>
    </div>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (6. 出貨統計查詢畫面)
# ==========================================
SHIP_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>出貨統計查詢</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; padding: 12px; margin: 0; background: #121212; color: #e0e0e0;}
        .search-box { position: sticky; top: 0; background: #1e1e1e; padding: 15px; z-index: 99; border-bottom: 1px solid #333; box-shadow: 0 4px 10px rgba(0,0,0,0.5); border-radius: 6px;}
        .search-container { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; max-width: 900px; margin: 0 auto; }
        input[type="date"] { padding: 10px; font-size: 15px; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; box-sizing: border-box; outline: none; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input[type="date"]:focus { border-color: #9e6a03; box-shadow: 0 0 0 2px rgba(158, 106, 3, 0.3); }
        
        /* 將原先 button 改為 a 標籤按鈕，100% 避開 Safari Bug */
        .action-btn { padding: 10px 18px; color: white; border-radius: 6px; font-weight: bold; cursor: pointer; transition: 0.2s; white-space: nowrap; font-size: 15px; display: flex; align-items: center; justify-content: center; text-decoration: none; box-sizing: border-box; border: none; }
        .action-btn:hover { filter: brightness(1.2); }
        .home-btn { background: #30363d; color: #c9d1d9; }
        .search-btn { background: #9e6a03; color: #fff; }
        
        .date-group { display: flex; align-items: center; white-space: nowrap; }
        .date-label { font-weight: bold; color: #8b949e; margin-right: 5px;}

        @media (max-width: 600px) {
            .search-container { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
            .home-btn, .search-btn { width: 100%; }
            .date-group.start, .date-group.end { grid-column: 1 / 3; justify-content: space-between; }
            .date-group input { flex-grow: 1; margin-left: 10px; width: 100%; }
        }

        /* 解決 Safari 邊線切開問題：改用 border-collapse: separate */
        .table-wrap { overflow-x: auto; background: #1e1e1e; border-radius: 6px; margin-top: 15px; max-width: 900px; margin-left: auto; margin-right: auto; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border: 1px solid #333;}
        table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; font-size: 15px; }
        th, td { border-bottom: 1px solid #333; border-right: 1px solid #333; padding: 12px; }
        th:last-child, td:last-child { border-right: none; }
        tbody tr:last-child td { border-bottom: none; }
        thead { background: #252526; color: #c9d1d9; }
        thead th { border-bottom: 2px solid #444; text-align: center; }
        
        .customer-row { cursor: pointer; background-color: #2a2a2a; transition: 0.2s; }
        .customer-row:hover { background-color: #383838; }
        .customer-name { font-weight: bold; font-size: 16px; color: #e3b341; }
        
        .date-row { cursor: pointer; background-color: #1e1e1e; transition: 0.2s; }
        .date-row:hover { background-color: #2c2c2c; }
        .detail-date { padding-left: 20px !important; color: #8b949e; font-weight: bold;}
        
        .item-row td { background-color: #121212; color: #aaa; font-size: 14px;}
        .item-name { padding-left: 50px !important; color: #c9d1d9; position: relative;}
        .toggle-icon { display: inline-block; width: 20px; font-size: 12px; color: #6e7681;}
        
        .total-row { background: #3d2e00; font-weight: bold; color: #e3b341; font-size: 16px;}
        .number-col { text-align: right; padding-right: 20px; }
        
        .return-badge { background: #4a1c1c; color: #ff7b72; border: 1px solid #8a2525; padding: 2px 6px; border-radius: 4px; font-size: 12px; margin-left: 10px; }
        
        .img-icon { display: inline-block; text-decoration: none; padding: 2px 5px; border-radius: 4px; transition: 0.2s; background: rgba(88, 166, 255, 0.1); border: 1px solid rgba(88, 166, 255, 0.2); font-size: 13px;}
        .img-icon:hover { background-color: #1f6feb; border-color: #1f6feb; filter: brightness(1.2);}
    </style>
</head>
<body>
    <div class="search-box">
        <div class="search-container">
            <a href="javascript:void(0)" class="action-btn home-btn" onclick="window.location.href='/'">🏠 回目錄</a>
            <div class="date-group start"><span class="date-label">起</span><input type="date" id="start_date"></div>
            <div class="date-group end"><span class="date-label">迄</span><input type="date" id="end_date"></div>
            <a href="javascript:void(0)" class="action-btn search-btn" onclick="searchShip()">🚚 查詢出貨</a>
        </div>
    </div>
    <div id="msg" style="color:#ff7b72; text-align:center; margin-top: 15px; font-weight: bold;"></div>
    
    <div class="table-wrap">
        <table id="list">
            <thead>
                <tr>
                    <th style="width: 40%;">客戶 / 出貨日期 / 明細</th>
                    <th class="number-col" style="width: 25%;">數量</th>
                    <th class="number-col" style="width: 35%;">金額</th>
                </tr>
            </thead>
            <tbody id="tbody">
                <tr><td colspan="3" style="color:#6e7681; padding: 30px; text-align: center; border-bottom: none;">請選擇日期區間並點擊查詢</td></tr>
            </tbody>
        </table>
    </div>

    <div id="imageModal" onclick="closeImage()" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.85); z-index:9999; justify-content:center; align-items:center;">
        <div style="position:relative; max-width:90%; max-height:90%; padding: 15px; background: #1e1e1e; border: 1px solid #444; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.8);" onclick="closeImage()">
            <img id="modalImg" src="" style="max-width:100%; max-height:80vh; display:block; margin:auto; border-radius: 6px;" alt="圖片載入中...">
        </div>
    </div>

    <script>
        const today = new Date().toISOString().split('T')[0];
        document.getElementById('start_date').value = today;
        document.getElementById('end_date').value = today;

        function showImage(filename) {
            const modal = document.getElementById('imageModal');
            const img = document.getElementById('modalImg');
            img.src = '/api/image?file=' + encodeURIComponent(filename);
            modal.style.display = 'flex';
        }

        function closeImage() {
            document.getElementById('imageModal').style.display = 'none';
            document.getElementById('modalImg').src = '';
        }

        function parseDateString(rawDate) {
            if (!rawDate) return '';
            let s = rawDate.trim();
            if (/^\\d{8}$/.test(s)) return `${s.substring(0,4)}-${s.substring(4,6)}-${s.substring(6,8)}`;
            if (s.length >= 10) return s.substring(0, 10);
            return s;
        }

        function toggleDisplay(targetId, iconId) {
            const el = document.getElementById(targetId);
            const icon = document.getElementById(iconId);
            if (el.style.display === 'none') { el.style.display = ''; icon.innerText = '▼'; } 
            else { el.style.display = 'none'; icon.innerText = '▶'; }
        }

        function toggleItems(className, iconId) {
            const rows = document.querySelectorAll('.' + className);
            const icon = document.getElementById(iconId);
            let isHidden = rows.length > 0 ? rows[0].style.display === 'none' : true;
            rows.forEach(r => { r.style.display = isHidden ? '' : 'none'; });
            icon.innerText = isHidden ? '▼' : '▶';
        }

        async function searchShip() {
            const startDate = document.getElementById('start_date').value;
            const endDate = document.getElementById('end_date').value;
            const msg = document.getElementById('msg');
            
            if(!startDate || !endDate) { msg.innerText = '請選擇完整的起迄日期！'; return; }
            if(startDate > endDate) { msg.innerText = '起始日期不能大於結束日期！'; return; }
            
            msg.style.color = '#58a6ff';
            msg.innerText = '查詢中，請稍候...';

            try {
                const res = await fetch(`/api/ship?start=${startDate}&end=${endDate}`);
                if (res.status === 401) { window.location.href = '/login'; return; }
                if (!res.ok) {
                    const errData = await res.json();
                    msg.style.color = '#ff7b72';
                    if(errData.error) { msg.innerHTML = `<b>${errData.error}</b>`; return; }
                }
                
                const data = await res.json();
                msg.innerText = '';
                if(data.error) { msg.style.color = '#ff7b72'; msg.innerText = data.error; return; }
                
                renderShipTable(data);
            } catch(e) { console.log(e); msg.style.color = '#ff7b72'; msg.innerText = '連線發生錯誤或系統已被鎖定'; }
        }

        function renderShipTable(data) {
            if (data.length === 0) {
                document.getElementById('tbody').innerHTML = '<tr><td colspan="3" style="color:#6e7681; padding:30px; text-align:center; border-bottom: none;">此區間無出退貨紀錄</td></tr>';
                return;
            }

            const grouped = {};
            let grandTotalQty = 0;
            let grandTotalAmt = 0;

            data.forEach(r => {
                let cId = r.custid || '未指名客戶';
                let cName = r.custname || '';
                let custDisplay = cName ? `${cId} - ${cName}` : cId;
                let dateStr = parseDateString(r.shipdate);
                
                let isReturn = (r.shipmode == 4);
                let qty = Number(r.detail_qty) || 0;
                let amt = Math.round(Number(r.detail_amount)) || 0;
                
                if (isReturn) {
                    qty = -Math.abs(qty);
                    amt = -Math.abs(amt);
                }

                if (!grouped[custDisplay]) { grouped[custDisplay] = { totalQty: 0, totalAmt: 0, days: {} }; }
                if (!grouped[custDisplay].days[dateStr]) { grouped[custDisplay].days[dateStr] = { totalQty: 0, totalAmt: 0, items: [] }; }
                
                grouped[custDisplay].days[dateStr].items.push({
                    goodid: r.goodid, goodname: r.goodname, qty: qty, amt: amt, isReturn: isReturn, imageFilename: r.ImageFilename
                });
                
                grouped[custDisplay].days[dateStr].totalQty += qty;
                grouped[custDisplay].days[dateStr].totalAmt += amt;
                grouped[custDisplay].totalQty += qty;
                grouped[custDisplay].totalAmt += amt;
                grandTotalQty += qty;
                grandTotalAmt += amt;
            });

            let html = '';
            let custIndex = 0;

            for (const [custDisplay, cData] of Object.entries(grouped)) {
                const custBodyId = `cust-${custIndex}`;
                const custIconId = `c-icon-${custIndex}`;

                html += `
                <tbody>
                    <tr class="customer-row" onclick="toggleDisplay('${custBodyId}', '${custIconId}')">
                        <td class="customer-name"><span id="${custIconId}" class="toggle-icon">▶</span> 👤 ${custDisplay}</td>
                        <td class="number-col" style="font-weight:bold; color:#fff;">${cData.totalQty.toLocaleString()}</td>
                        <td class="number-col" style="font-weight:bold; color:#fff;">$ ${cData.totalAmt.toLocaleString()}</td>
                    </tr>
                </tbody>
                <tbody id="${custBodyId}" style="display: none;">`;
                
                let dateIndex = 0;
                const sortedDates = Object.keys(cData.days).sort().reverse(); 
                
                sortedDates.forEach(dateStr => {
                    let dayData = cData.days[dateStr];
                    const itemClass = `items-${custIndex}-${dateIndex}`;
                    const dateIconId = `d-icon-${custIndex}-${dateIndex}`;
                    
                    html += `
                    <tr class="date-row" onclick="toggleItems('${itemClass}', '${dateIconId}')">
                        <td class="detail-date"><span id="${dateIconId}" class="toggle-icon">▶</span>  📅 ${dateStr}</td>
                        <td class="number-col" style="color:#8b949e;">${dayData.totalQty.toLocaleString()}</td>
                        <td class="number-col" style="color:#8b949e;">$ ${dayData.totalAmt.toLocaleString()}</td>
                    </tr>`;

                    dayData.items.forEach(item => {
                        let badge = item.isReturn ? '<span class="return-badge">退貨</span>' : '';
                        let itemName = item.goodname ? ` - <span style="color:#8b949e">${item.goodname}</span>` : '';
                        
                        let imgIcon = '';
                        if (item.imageFilename && item.imageFilename.trim() !== '') {
                            imgIcon = `<a href="javascript:void(0)" class="img-icon" style="position:absolute; left:12px; top:50%; transform:translateY(-50%); margin:0;" onclick="showImage('${item.imageFilename}')" title="點擊查看圖片">🖼️</a>`;
                        }

                        html += `
                        <tr class="item-row ${itemClass}" style="display: none;">
                            <td class="item-name">${imgIcon}<span style="color:#444; margin-right:5px;">▪</span> ${item.goodid}${itemName} ${badge}</td>
                            <td class="number-col">${item.qty.toLocaleString()}</td>
                            <td class="number-col">$ ${item.amt.toLocaleString()}</td>
                        </tr>`;
                    });
                    dateIndex++;
                });
                html += `</tbody>`;
                custIndex++;
            }

            html += `
            <tbody>
                <tr class="total-row">
                    <td style="text-align: right; padding-right: 15px;">全客戶區間總計：</td>
                    <td class="number-col">${grandTotalQty.toLocaleString()}</td>
                    <td class="number-col">$ ${grandTotalAmt.toLocaleString()}</td>
                </tr>
            </tbody>`;

            document.getElementById('list').innerHTML = `
                <thead>
                    <tr>
                        <th style="width: 40%;">客戶 / 出貨日期 / 明細</th>
                        <th class="number-col" style="width: 25%;">數量</th>
                        <th class="number-col" style="width: 35%;">金額</th>
                    </tr>
                </thead>
                ${html}`;
        }
    </script>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (7. 銷售業績查詢畫面)
# ==========================================
SALES_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>銷售業績查詢</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; padding: 12px; margin: 0; background: #121212; color: #e0e0e0;}
        .search-box { position: sticky; top: 0; background: #1e1e1e; padding: 15px; z-index: 99; border-bottom: 1px solid #333; box-shadow: 0 4px 10px rgba(0,0,0,0.5); border-radius: 6px;}
        .search-container { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; max-width: 900px; margin: 0 auto; }
        input[type="date"] { padding: 10px; font-size: 15px; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; box-sizing: border-box; outline: none; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input[type="date"]:focus { border-color: #1f6feb; box-shadow: 0 0 0 2px rgba(31, 111, 235, 0.3); }
        
        /* 將原先 button 改為 a 標籤按鈕，100% 避開 Safari Bug */
        .action-btn { padding: 10px 18px; color: white; border-radius: 6px; font-weight: bold; cursor: pointer; transition: 0.2s; white-space: nowrap; font-size: 15px; display: flex; align-items: center; justify-content: center; text-decoration: none; box-sizing: border-box; border: none; }
        .action-btn:hover { filter: brightness(1.2); }
        .home-btn { background: #30363d; color: #c9d1d9; }
        .search-btn { background: #1f6feb; color: #fff; }
        
        .date-group { display: flex; align-items: center; white-space: nowrap; }
        .date-label { font-weight: bold; color: #8b949e; margin-right: 5px;}

        @media (max-width: 600px) {
            .search-container { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
            .home-btn { order: 1; width: 100%; }
            .search-btn { order: 2; width: 100%; }
            .date-group.start { order: 3; grid-column: 1 / 3; }
            .date-group.end { order: 4; grid-column: 1 / 3; }
            .date-group { justify-content: space-between; }
            .date-group input { flex-grow: 1; margin-left: 10px; width: 100%; }
        }

        /* 解決 Safari 邊線切開問題：改用 border-collapse: separate */
        .table-wrap { overflow-x: auto; background: #1e1e1e; border-radius: 6px; margin-top: 15px; max-width: 900px; margin-left: auto; margin-right: auto; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border: 1px solid #333;}
        table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; font-size: 15px; }
        th, td { border-bottom: 1px solid #333; border-right: 1px solid #333; padding: 12px; }
        th:last-child, td:last-child { border-right: none; }
        tbody tr:last-child td { border-bottom: none; }
        thead { background: #252526; color: #c9d1d9; }
        thead th { border-bottom: 2px solid #444; text-align: center; }
        
        .sortable { cursor: pointer; user-select: none; transition: 0.2s; }
        .sortable:hover { background-color: #333; color: #fff;}
        
        .branch-row { cursor: pointer; background-color: #2a2a2a; transition: 0.2s; }
        .branch-row:hover { background-color: #383838; }
        .branch-name { font-weight: bold; font-size: 16px; color: #58a6ff; }
        
        .date-row { cursor: pointer; background-color: #1e1e1e; transition: 0.2s; }
        .date-row:hover { background-color: #2c2c2c; }
        .detail-date { padding-left: 20px !important; color: #8b949e; font-weight: bold;}
        
        .item-row td { background-color: #121212; color: #aaa; font-size: 14px;}
        .item-name { padding-left: 50px !important; color: #c9d1d9; position: relative;}
        .toggle-icon { display: inline-block; width: 20px; font-size: 12px; color: #6e7681;}
        
        .total-row { background: #221626; font-weight: bold; color: #d2a8ff; font-size: 16px;}
        .money { text-align: right; padding-right: 20px; font-weight: bold; color: #fff;}
        .money-detail { text-align: right; padding-right: 20px; color: #c9d1d9; }
        .money-item { text-align: right; padding-right: 20px; color: #8b949e; }
        
        .img-icon { display: inline-block; text-decoration: none; padding: 2px 5px; border-radius: 4px; transition: 0.2s; background: rgba(88, 166, 255, 0.1); border: 1px solid rgba(88, 166, 255, 0.2); font-size: 13px;}
        .img-icon:hover { background-color: #1f6feb; border-color: #1f6feb; filter: brightness(1.2);}
    </style>
</head>
<body>
    <div class="search-box">
        <div class="search-container">
            <a href="javascript:void(0)" class="action-btn home-btn" onclick="window.location.href='/'">🏠 回目錄</a>
            <div class="date-group start">
                <span class="date-label">起</span>
                <input type="date" id="start_date">
            </div>
            <div class="date-group end">
                <span class="date-label">迄</span>
                <input type="date" id="end_date">
            </div>
            <a href="javascript:void(0)" class="action-btn search-btn" onclick="searchSales()">🔍 查詢業績</a>
        </div>
    </div>
    <div id="msg" style="color:#ff7b72; text-align:center; margin-top: 15px; font-weight:bold;"></div>
    
    <div class="table-wrap">
        <table id="list">
            <thead>
                <tr>
                    <th class="sortable" style="width: 40%;">銷售分店</th>
                    <th class="sortable" style="width: 25%; text-align: right; padding-right: 20px;">銷售金額</th>
                    <th style="width: 35%;">品名 / 說明</th>
                </tr>
            </thead>
            <tbody id="tbody">
                <tr><td colspan="3" style="color:#6e7681; padding: 30px; text-align: center; border-bottom: none;">請選擇日期區間並點擊查詢</td></tr>
            </tbody>
        </table>
    </div>

    <div id="imageModal" onclick="closeImage()" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.85); z-index:9999; justify-content:center; align-items:center;">
        <div style="position:relative; max-width:90%; max-height:90%; padding: 15px; background: #1e1e1e; border: 1px solid #444; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.8);" onclick="closeImage()">
            <img id="modalImg" src="" style="max-width:100%; max-height:80vh; display:block; margin:auto; border-radius: 6px;" alt="圖片載入中...">
        </div>
    </div>

    <script>
        const today = new Date().toISOString().split('T')[0];
        document.getElementById('start_date').value = today;
        document.getElementById('end_date').value = today;

        let currentSalesData = [];
        let salesSortState = { col: 'sellbranch', asc: true }; 

        function showImage(filename) {
            const modal = document.getElementById('imageModal');
            const img = document.getElementById('modalImg');
            img.src = '/api/image?file=' + encodeURIComponent(filename);
            modal.style.display = 'flex';
        }

        function closeImage() {
            document.getElementById('imageModal').style.display = 'none';
            document.getElementById('modalImg').src = '';
        }

        function parseDateString(rawDate) {
            if (!rawDate) return '';
            let s = rawDate.trim();
            if (/^\\d{8}$/.test(s)) {
                return `${s.substring(0,4)}-${s.substring(4,6)}-${s.substring(6,8)}`;
            }
            if (s.length >= 10) return s.substring(0, 10);
            return s;
        }

        function getWeekday(formattedDate) {
            if (!formattedDate) return '';
            const days = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
            let parts = formattedDate.split('-');
            if (parts.length === 3) {
                let d = new Date(parts[0], parseInt(parts[1], 10) - 1, parts[2]);
                return days[d.getDay()];
            }
            return '';
        }

        function toggleDetails(branchId, iconId) {
            const tbody = document.getElementById(branchId);
            const icon = document.getElementById(iconId);
            if (tbody.style.display === 'none') {
                tbody.style.display = '';
                icon.innerText = '▼';
            } else {
                tbody.style.display = 'none';
                icon.innerText = '▶';
            }
        }

        function toggleItems(className, iconId) {
            const rows = document.querySelectorAll('.' + className);
            const icon = document.getElementById(iconId);
            let isHidden = true;
            if(rows.length > 0) { isHidden = rows[0].style.display === 'none'; }
            rows.forEach(r => { r.style.display = isHidden ? '' : 'none'; });
            icon.innerText = isHidden ? '▼' : '▶';
        }

        async function searchSales() {
            const startDate = document.getElementById('start_date').value;
            const endDate = document.getElementById('end_date').value;
            const msg = document.getElementById('msg');
            
            if(!startDate || !endDate) { msg.innerText = '請選擇完整的起迄日期！'; return; }
            if(startDate > endDate) { msg.innerText = '起始日期不能大於結束日期！'; return; }
            
            msg.style.color = '#58a6ff';
            msg.innerText = '查詢中，請稍候...';

            try {
                const res = await fetch(`/api/sales?start=${startDate}&end=${endDate}`);
                if (res.status === 401) { window.location.href = '/login'; return; }
                
                if (!res.ok) {
                    const errData = await res.json();
                    msg.style.color = '#ff7b72';
                    if(errData.error) { msg.innerHTML = `<b>${errData.error}</b>`; return; }
                }
                
                const data = await res.json();
                msg.innerText = '';

                if(data.error) { msg.style.color = '#ff7b72'; msg.innerText = data.error; return; }
                
                currentSalesData = data;
                salesSortState = { col: 'sellbranch', asc: true }; 
                renderSalesTable();

            } catch(e) { console.log(e); msg.style.color = '#ff7b72'; msg.innerText = '連線發生錯誤或系統已被鎖定'; }
        }

        function sortSalesTable(col) {
            if (currentSalesData.length === 0) return;
            if (salesSortState.col === col) {
                salesSortState.asc = !salesSortState.asc; 
            } else {
                salesSortState.col = col; 
                salesSortState.asc = true;
            }
            renderSalesTable();
        }

        function renderSalesTable() {
            let displayData = currentSalesData;

            if (displayData.length === 0) {
                document.getElementById('list').innerHTML = `
                    <thead>
                        <tr>
                            <th class="sortable" style="width: 40%;" onclick="sortSalesTable('sellbranch')">銷售分店 <span id="s-icon-sellbranch">▲</span></th>
                            <th class="sortable" style="width: 25%; text-align: right; padding-right: 20px;" onclick="sortSalesTable('total')">銷售金額 <span id="s-icon-total"></span></th>
                            <th style="width: 35%;">品名 / 說明</th>
                        </tr>
                    </thead>
                    <tbody><tr><td colspan="3" style="color:#6e7681; padding:30px; text-align:center; border-bottom: none;">此區間無銷售紀錄</td></tr></tbody>`;
                return;
            }

            const grouped = {};
            let grandTotal = 0;

            displayData.forEach(r => {
                let bId = r.sellbranch || '未指名分店';
                let bName = r.branchname || '';
                let branchDisplay = bName ? `${bId} - ${bName}` : bId;
                
                let goodId = r.goodid || '未知商品';
                let goodName = r.goodname || ''; 
                
                let price = Math.round(Number(r.sellprice)) || 0;
                let stock = Number(r.current_stock) || 0;
                
                let dateStr = parseDateString(r.selldate);

                if (!grouped[branchDisplay]) { grouped[branchDisplay] = { sellbranch: branchDisplay, total: 0, days: {} }; }
                if (!grouped[branchDisplay].days[dateStr]) { grouped[branchDisplay].days[dateStr] = { total: 0, items: {} }; }
                
                if (!grouped[branchDisplay].days[dateStr].items[goodId]) { 
                    // 紀錄該商品庫存量
                    grouped[branchDisplay].days[dateStr].items[goodId] = { total: 0, name: goodName, imageFilename: r.ImageFilename, stock: stock }; 
                }

                grouped[branchDisplay].days[dateStr].items[goodId].total += price;
                grouped[branchDisplay].days[dateStr].total += price;
                grouped[branchDisplay].total += price;
                grandTotal += price;
            });

            let groupedArray = Object.values(grouped);

            groupedArray.sort((a, b) => {
                let valA = a[salesSortState.col];
                let valB = b[salesSortState.col];
                
                if (salesSortState.col === 'total') {
                    valA = Number(valA);
                    valB = Number(valB);
                } else {
                    valA = String(valA).toLowerCase();
                    valB = String(valB).toLowerCase();
                }

                if (valA < valB) return salesSortState.asc ? -1 : 1;
                if (valA > valB) return salesSortState.asc ? 1 : -1;
                return 0;
            });

            let html = '';
            groupedArray.forEach((bData, index) => {
                const branchBodyId = `detail-${index}`;
                const branchIconId = `icon-${index}`;

                html += `
                <tbody>
                    <tr class="branch-row" onclick="toggleDetails('${branchBodyId}', '${branchIconId}')">
                        <td class="branch-name">
                            <span id="${branchIconId}" class="toggle-icon">▶</span> ${bData.sellbranch}
                        </td>
                        <td class="money">$ ${bData.total.toLocaleString()}</td>
                        <td style="color:#6e7681; text-align:left; padding-left:15px; font-size:13px;">分店總計</td>
                    </tr>
                </tbody>`;

                html += `<tbody id="${branchBodyId}" style="display: none;">`;
                
                const sortedDates = Object.keys(bData.days).sort();
                sortedDates.forEach((dateStr, dateIndex) => {
                    let dayData = bData.days[dateStr];
                    let weekday = getWeekday(dateStr);
                    
                    const itemClass = `items-group-${index}-${dateIndex}`;
                    const dateIconId = `date-icon-${index}-${dateIndex}`;
                    
                    html += `
                    <tr class="date-row" onclick="toggleItems('${itemClass}', '${dateIconId}')">
                        <td class="detail-date">
                            <span id="${dateIconId}" class="toggle-icon">▶</span>  ${dateStr} (${weekday})
                        </td>
                        <td class="money-detail">$ ${dayData.total.toLocaleString()}</td>
                        <td style="color:#6e7681; text-align:left; padding-left:15px; font-size:13px;">日總計</td>
                    </tr>`;

                    const sortedItems = Object.keys(dayData.items).sort();
                    sortedItems.forEach(gId => {
                        let itemTotal = dayData.items[gId].total;
                        let itemName = dayData.items[gId].name || '未提供品名'; 
                        let imgFilename = dayData.items[gId].imageFilename;
                        let stock = dayData.items[gId].stock;
                        let isOutOfStock = stock <= 0;
                        
                        let imgIcon = '';
                        if (imgFilename && imgFilename.trim() !== '') {
                            imgIcon = `<a href="javascript:void(0)" class="img-icon" style="position:absolute; left:12px; top:50%; transform:translateY(-50%); margin:0;" onclick="showImage('${imgFilename}')" title="點擊查看圖片">🖼️</a>`;
                        }
                        
                        // 若無庫存，文字轉紅並加上標籤 (修改：標籤移到品名前面)
                        let itemStyle = isOutOfStock ? 'color:#ff7b72; font-weight:bold;' : 'color:#c9d1d9;';
                        let badge = isOutOfStock ? '<span style="background:#4a1c1c; color:#ff7b72; border:1px solid #8a2525; padding:2px 4px; border-radius:4px; font-size:11px; margin-right:6px; vertical-align:middle;">缺貨</span>' : '';
                        
                        html += `
                        <tr class="item-row ${itemClass}" style="display: none;">
                            <td class="item-name" style="${itemStyle}">
                                ${imgIcon}<span style="color:#444; margin-right:5px;">▪</span> ${gId}
                            </td>
                            <td class="money-item">$ ${itemTotal.toLocaleString()}</td>
                            <td style="color:#8b949e; text-align:left; font-size: 0.9em; padding-left:15px; vertical-align:middle;">${badge}${itemName}</td>
                        </tr>`;
                    });
                });
                html += `</tbody>`;
            });

            html += `
            <tbody>
                <tr class="total-row">
                    <td style="text-align: right; padding-right: 15px;">全部分店區間總計：</td>
                    <td style="text-align: right; padding-right: 20px; font-weight: bold;">$ ${grandTotal.toLocaleString()}</td>
                    <td></td>
                </tr>
            </tbody>`;

            let iconBranch = salesSortState.col === 'sellbranch' ? (salesSortState.asc ? ' ▲' : ' ▼') : '';
            let iconTotal = salesSortState.col === 'total' ? (salesSortState.asc ? ' ▲' : ' ▼') : '';

            document.getElementById('list').innerHTML = `
                <thead>
                    <tr>
                        <th class="sortable" style="width: 40%;" onclick="sortSalesTable('sellbranch')">銷售分店<span style="color:#58a6ff">${iconBranch}</span></th>
                        <th class="sortable" style="width: 25%; text-align: right; padding-right: 20px;" onclick="sortSalesTable('total')">銷售金額<span style="color:#58a6ff">${iconTotal}</span></th>
                        <th style="width: 35%;">品名 / 說明</th>
                    </tr>
                </thead>
                ${html}
            `;
        }
    </script>
</body>
</html>
"""

# ==========================================
# 🟢 前端畫面 (8. 庫存查詢主畫面) 
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>庫存查詢</title>
    <style>
        :root { color-scheme: dark; }
        body { font-family: sans-serif; padding: 12px; margin: 0; background: #121212; color: #e0e0e0; }
        .search-box { position: sticky; top: 0; background: #1e1e1e; padding: 15px; z-index: 99; border-bottom: 1px solid #333; box-shadow: 0 4px 10px rgba(0,0,0,0.5); border-radius: 6px; }
        .search-container { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; max-width: 1200px; margin: 0 auto; }
        input[type="text"] { flex: 1; padding: 12px; font-size: 16px; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 6px; box-sizing: border-box; outline: none; transition: 0.3s; -webkit-appearance: none; appearance: none; background-image: none; background-clip: padding-box;}
        input[type="text"]:focus { border-color: #238636; box-shadow: 0 0 0 3px rgba(35, 134, 54, 0.3); }
        
        /* 將原先 button 改為 a 標籤按鈕，100% 避開 Safari Bug */
        .action-btn { padding: 12px 20px; color: white; border-radius: 6px; font-weight: bold; cursor: pointer; white-space: nowrap; font-size: 15px; transition: 0.2s; display: flex; align-items: center; justify-content: center; text-decoration: none; box-sizing: border-box; border: none; }
        .action-btn:hover { filter: brightness(1.15); }
        .home-btn { background: #30363d; color: #c9d1d9; }
        .search-btn { background: #238636; color: #fff; }
        
        .toggle-label { display: flex; align-items: center; cursor: pointer; font-weight: bold; font-size: 15px; color: #c9d1d9; user-select: none; white-space: nowrap; padding: 0 5px;}
        input[type="checkbox"] { width: 18px; height: 18px; margin-right: 8px; cursor: pointer; accent-color: #238636;}
        .input-group { display: flex; gap: 8px; flex-grow: 1; }

        @media (max-width: 600px) {
            .search-container { flex-direction: column; align-items: stretch; gap: 12px; }
            .home-btn { width: 100%; }
            .input-group { display: flex; width: 100%; }
            .input-group input { width: 100%; }
            .toggle-label { justify-content: center; background: #252526; padding: 10px; border-radius: 6px; border: 1px solid #333;}
        }

        /* 解決 Safari 邊線切開問題：改用 border-collapse: separate */
        .table-wrap { overflow-x: auto; background: #1e1e1e; border-radius: 6px; margin-top: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border: 1px solid #333;}
        table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; font-size: 14px; color: #c9d1d9; }
        th, td { border-bottom: 1px solid #333; border-right: 1px solid #333; padding: 10px 8px; text-align: center; min-width: 35px; }
        th:last-child, td:last-child { border-right: none; }
        tbody tr:last-child td { border-bottom: none; }
        thead { background: #252526; color: #fff; }
        thead th { border-bottom: 2px solid #444; }
        .sortable { cursor: pointer; user-select: none; transition: 0.2s;}
        .sortable:hover { background-color: #333; }
        
        .sticky { position: sticky; left: 0; background: #1e1e1e; z-index: 10; font-weight: bold;}
        thead th.sticky { background: #252526; color: #fff; z-index: 20;}
        
        .total { background: #1a2a3a; color: #58a6ff; font-weight: bold; }
        .size-header-row td { font-weight: bold; font-size: 0.95em; border-bottom: 1px solid #444; }
        .size-label { text-align: right !important; padding-right: 12px; }
        
        .size-row-1 td { background-color: #3d2e00; color: #e3b341; }
        .size-row-2 td { background-color: #102a3a; color: #58a6ff; }
        .size-row-3 td { background-color: #1b3a20; color: #3fb950; }
        
        .subtotal-row td { background-color: #24292f !important; color: #58a6ff; font-weight: bold; border-top: 2px solid #1f6feb; border-bottom: 2px solid #1f6feb; }
        .subtotal-row td.sticky { background-color: #24292f !important; z-index: 10; }
        
        .store-name { display: block; font-size: 0.8em; color: #8b949e; margin-top: 3px; }
        
        /* 獨立圖片圖示樣式 */
        .model-cell { display: flex; align-items: center; justify-content: flex-start; }
        .icon-container { width: 36px; display: flex; justify-content: center; flex-shrink: 0; }
        .img-icon { display: inline-block; text-decoration: none; padding: 2px 5px; border-radius: 4px; transition: 0.2s; background: rgba(88, 166, 255, 0.1); border: 1px solid rgba(88, 166, 255, 0.2); font-size: 13px;}
        .img-icon:hover { background-color: #1f6feb; border-color: #1f6feb; filter: brightness(1.2);}
        
        tbody tr:hover td:not(.sticky):not(.size-label) { background-color: #2c2c2c; }
    </style>
</head>
<body>
    <div class="search-box">
        <div class="search-container">
            <a href="javascript:void(0)" class="action-btn home-btn" onclick="window.location.href='/'">🏠 回目錄</a>
            <div class="input-group">
                <input type="text" id="q" placeholder="輸入貨號..." oninput="search()">
                <a href="javascript:void(0)" class="action-btn search-btn" onclick="search()">查 詢</a>
            </div>
            <label class="toggle-label">
                <input type="checkbox" id="hideZero" onchange="renderTable()" checked> 隱藏無庫存
            </label>
        </div>
    </div>
    <div id="msg" style="color:#58a6ff; text-align:center; margin-top: 15px; font-weight: bold;"></div>
    
    <div class="table-wrap">
        <table id="list">
            <thead>
                <tr>
                    <th class="sticky sortable" onclick="sortTable('GoodID')">型號 <span id="icon-GoodID"></span></th>
                    <th class="sortable" onclick="sortTable('Store')">分店 <span id="icon-Store"></span></th>
                    <th class="total sortable" onclick="sortTable('StorageTotalNum')">合計 <span id="icon-StorageTotalNum"></span></th>
                    
                    <th style="color:#8b949e;">段碼</th>
                    <th></th><th></th><th></th><th></th><th></th>
                    <th></th><th></th><th></th><th></th><th></th>
                    <th></th><th></th><th></th><th></th><th></th>
                    <th></th><th></th>
                </tr>
            </thead>
            <tbody id="tbody"></tbody>
        </table>
    </div>

    <div id="imageModal" onclick="closeImage()" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.85); z-index:9999; justify-content:center; align-items:center;">
        <div style="position:relative; max-width:90%; max-height:90%; padding: 15px; background: #1e1e1e; border: 1px solid #444; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.8);" onclick="closeImage()">
            <img id="modalImg" src="" style="max-width:100%; max-height:80vh; display:block; margin:auto; border-radius: 6px;" alt="圖片載入中...">
        </div>
    </div>

    <script>
        let timer;
        let currentData = []; 
        let sortState = { col: 'GoodID', asc: true }; 

        function search() {
            clearTimeout(timer);
            timer = setTimeout(runQuery, 500);
        }

        async function runQuery() {
            const val = document.getElementById('q').value.trim();
            const msg = document.getElementById('msg');
            const tbody = document.getElementById('tbody');
            
            if(!val) { tbody.innerHTML=''; return; }
            msg.style.color = '#58a6ff';
            msg.innerText = '查詢中...';

            try {
                const res = await fetch('/api/search?q=' + encodeURIComponent(val));
                if (res.status === 401) { window.location.href = '/login'; return; }
                if (!res.ok) {
                    const errData = await res.json();
                    msg.style.color = '#ff7b72';
                    if(errData.error) { msg.innerHTML = `<b>${errData.error}</b>`; return; }
                }
                const data = await res.json();
                msg.innerText = '';

                if(data.error) { msg.style.color = '#ff7b72'; msg.innerText = data.error; return; }
                if(data.length === 0) { tbody.innerHTML = '<tr><td colspan="21" style="color:#8b949e; padding:30px; border-bottom: none;">查無資料</td></tr>'; return; }

                currentData = data.map(r => {
                    let realTotal = 0;
                    for(let i = 1; i <= 17; i++) {
                        let numStr = i.toString().padStart(2, '0');
                        let val = r['StorageNum' + numStr];
                        if (val) { realTotal += Number(val); }
                    }
                    r.StorageTotalNum = realTotal;
                    return r;
                });

                sortState = { col: 'GoodID', asc: true };
                updateSortIcons();
                renderTable();

            } catch(e) { console.log(e); msg.style.color = '#ff7b72'; msg.innerText = '連線錯誤或系統已被鎖定'; }
        }

        function showImage(filename) {
            const modal = document.getElementById('imageModal');
            const img = document.getElementById('modalImg');
            img.src = '/api/image?file=' + encodeURIComponent(filename); 
            modal.style.display = 'flex';
        }

        function closeImage() {
            document.getElementById('imageModal').style.display = 'none';
            document.getElementById('modalImg').src = '';
        }

        function sortTable(col) {
            if (currentData.length === 0) return;
            if (sortState.col === col) { sortState.asc = !sortState.asc; } 
            else { sortState.col = col; sortState.asc = true; }

            currentData.sort((a, b) => {
                let valA = a[col];
                let valB = b[col];

                if (col === 'StorageTotalNum') {
                    valA = Number(valA || 0);
                    valB = Number(valB || 0);
                } else {
                    valA = (valA || '').toString().toLowerCase();
                    valB = (valB || '').toString().toLowerCase();
                }

                if (valA < valB) return sortState.asc ? -1 : 1;
                if (valA > valB) return sortState.asc ? 1 : -1;
                return 0;
            });

            updateSortIcons();
            renderTable();
        }

        function updateSortIcons() {
            ['GoodID', 'Store', 'StorageTotalNum'].forEach(id => {
                document.getElementById('icon-' + id).innerText = '';
            });
            const icon = sortState.asc ? '▲' : '▼';
            const target = document.getElementById('icon-' + sortState.col);
            if(target) target.innerHTML = `<span style="color:#2ea043; margin-left:4px;">${icon}</span>`;
        }

        function renderTable() {
            const tbody = document.getElementById('tbody');
            let html = '';
            let lastSizeNo1 = null;
            let lastSizeNo2 = null;
            let lastSizeNo3 = null;

            const hideZero = document.getElementById('hideZero').checked;
            let displayData = currentData;
            
            if (hideZero) {
                displayData = currentData.filter(r => r.StorageTotalNum !== 0);
            }

            if (displayData.length === 0 && currentData.length > 0) {
                tbody.innerHTML = '<tr><td colspan="21" style="padding: 30px; color: #8b949e; border-bottom: none;">該款式目前各分店皆無庫存。</td></tr>';
                return;
            }

            let isSortedByGoodID = (sortState.col === 'GoodID');
            let subTotals = { total: 0, nums: new Array(17).fill(0) };
            let lastGoodID = null;
            
            const f = (v) => (v === null || v === 0) ? '' : v;

            const flushSubTotal = () => {
                if (lastGoodID !== null && isSortedByGoodID) {
                    let trHtml = `<tr class="subtotal-row">
                        <td class="sticky" style="text-align:right;">${lastGoodID} 合計 </td>
                        <td style="color:#444;">-</td>
                        <td class="total" style="background-color: transparent !important;">${subTotals.total || ''}</td>
                        <td style="color:#444;">-</td>`;
                    for(let i = 0; i < 17; i++) {
                        trHtml += `<td>${f(subTotals.nums[i])}</td>`;
                    }
                    trHtml += `</tr>`;
                    html += trHtml;
                }
            };

            displayData.forEach(r => {
                if (isSortedByGoodID) {
                    if (lastGoodID !== null && r.GoodID !== lastGoodID) {
                        flushSubTotal();
                        subTotals = { total: 0, nums: new Array(17).fill(0) };
                        lastSizeNo1 = null; lastSizeNo2 = null; lastSizeNo3 = null; 
                    }
                    lastGoodID = r.GoodID;
                    subTotals.total += Number(r.StorageTotalNum || 0);
                    for(let i = 1; i <= 17; i++) {
                        let numStr = i.toString().padStart(2, '0');
                        subTotals.nums[i-1] += Number(r['StorageNum' + numStr] || 0);
                    }
                }

                if (r.SizeNo1 !== lastSizeNo1) {
                    if (r.SizeNo1) {
                        html += `<tr class="size-header-row size-row-1"><td class="sticky size-label">段碼 ${r.SizeNo1} </td><td colspan="3"></td>`;
                        for(let i=1; i<=17; i++) { html += `<td>${r['S1_' + i.toString().padStart(2, '0')] || ''}</td>`; }
                        html += `</tr>`;
                    }
                    lastSizeNo1 = r.SizeNo1;
                }
                
                if (r.SizeNo2 !== lastSizeNo2) {
                    if (r.SizeNo2) {
                        html += `<tr class="size-header-row size-row-2"><td class="sticky size-label">段碼 ${r.SizeNo2} </td><td colspan="3"></td>`;
                        for(let i=1; i<=17; i++) { html += `<td>${r['S2_' + i.toString().padStart(2, '0')] || ''}</td>`; }
                        html += `</tr>`;
                    }
                    lastSizeNo2 = r.SizeNo2;
                }
                
                if (r.SizeNo3 !== lastSizeNo3) {
                    if (r.SizeNo3) {
                        html += `<tr class="size-header-row size-row-3"><td class="sticky size-label">段碼 ${r.SizeNo3} </td><td colspan="3"></td>`;
                        for(let i=1; i<=17; i++) { html += `<td>${r['S3_' + i.toString().padStart(2, '0')] || ''}</td>`; }
                        html += `</tr>`;
                    }
                    lastSizeNo3 = r.SizeNo3;
                }

                let sizeList = [r.SizeNo1, r.SizeNo2, r.SizeNo3].filter(v => v && v.trim() !== '').join(' / ');
                let storeDisplay = r.StoreName ? `${r.Store}<span class="store-name">${r.StoreName}</span>` : r.Store;
                
                let imgIcon = `<div class="icon-container"></div>`;
                if (r.ImageFilename && r.ImageFilename.trim() !== '') {
                    imgIcon = `<div class="icon-container"><a href="javascript:void(0)" class="img-icon" onclick="showImage('${r.ImageFilename}')" title="點擊查看圖片">🖼️</a></div>`;
                }
                let goodIdDisplay = `<div class="model-cell">${imgIcon}<span>${r.GoodID}</span></div>`;

                html += `<tr>
                    <td class="sticky" style="text-align:left; padding: 10px 4px;">${goodIdDisplay}</td>
                    <td>${storeDisplay}</td><td class="total">${f(r.StorageTotalNum)}</td>
                    <td style="color:#8b949e;font-size:0.85em">${sizeList}</td>
                    <td>${f(r.StorageNum01)}</td><td>${f(r.StorageNum02)}</td><td>${f(r.StorageNum03)}</td>
                    <td>${f(r.StorageNum04)}</td><td>${f(r.StorageNum05)}</td><td>${f(r.StorageNum06)}</td>
                    <td>${f(r.StorageNum07)}</td><td>${f(r.StorageNum08)}</td><td>${f(r.StorageNum09)}</td>
                    <td>${f(r.StorageNum10)}</td><td>${f(r.StorageNum11)}</td><td>${f(r.StorageNum12)}</td>
                    <td>${f(r.StorageNum13)}</td><td>${f(r.StorageNum14)}</td><td>${f(r.StorageNum15)}</td>
                    <td>${f(r.StorageNum16)}</td><td>${f(r.StorageNum17)}</td>
                </tr>`;
            });

            if (isSortedByGoodID && displayData.length > 0) {
                flushSubTotal();
            }

            tbody.innerHTML = html;
        }
    </script>
</body>
</html>
""" 

# ------------------------------------------------
# 3. 後端 API 與 路由
# ------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    config = load_db_config()
    app_title = config.get('APP_TITLE', 'WebScout')
    error = None
    
    if request.method == 'POST':
        userid = request.form.get('userid', '').strip()
        password = request.form.get('password', '').strip()
        
        # 系統維護後門 (不納入裝置數量計算)
        if userid == 'SYS_MAINTENANCE_MODE':
            if password == 'admin5896':
                session['logged_in'] = True
                session['userid'] = '系統維護員'
                session['settings_unlocked'] = True
                return redirect(url_for('settings_page'))
            else:
                error = '維護密碼錯誤！'
                return render_template_string(LOGIN_TEMPLATE, error=error, app_title=app_title)
        
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                sql = "SELECT USERID, PASSWORD FROM USERS WHERE RTRIM(LTRIM(USERID)) = ?"
                cursor.execute(sql, (userid,))
                user = cursor.fetchone()
                
                if user:
                    db_encrypted_pwd = user.PASSWORD
                    db_decrypted_pwd = decrypt_password(db_encrypted_pwd)
                    
                    if db_decrypted_pwd == password:
                        # ---- 裝置綁定檢查 ----
                        device_id = request.cookies.get('device_id')
                        if not device_id:
                            device_id = uuid.uuid4().hex

                        allowed_devices = load_devices()
                        current_max_devices = LICENSE_CACHE.get('max_devices', 5) # 取得動態上限
                        
                        # 如果此裝置不在白名單內
                        if device_id not in allowed_devices:
                            if len(allowed_devices) >= current_max_devices:
                                error = f'⛔ 登入失敗：已達系統最大授權裝置數量 ({current_max_devices}/{current_max_devices})！<br>此裝置未被授權，請聯絡管理員清除舊裝置。'
                                return render_template_string(LOGIN_TEMPLATE, error=error, app_title=app_title)
                            else:
                                # 註冊新裝置
                                allowed_devices[device_id] = {
                                    'userid': userid,
                                    'bind_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                }
                                save_devices(allowed_devices)
                        
                        # 登入成功
                        session['logged_in'] = True
                        session['userid'] = userid
                        
                        # 將 Cookie 壽命設為 10 年，除非手動清除瀏覽器紀錄
                        resp = make_response(redirect(url_for('index')))
                        resp.set_cookie('device_id', device_id, max_age=315360000) 
                        return resp
                    else:
                        error = '密碼錯誤！'
                else:
                    error = '帳號錯誤！'
            except Exception as e:
                error = f'資料庫查詢發生錯誤: {e}'
            finally:
                conn.close()
        else:
            error = '無法連線至資料庫！請檢查系統連線設定。'
    return render_template_string(LOGIN_TEMPLATE, error=error, app_title=app_title)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    session.pop('settings_unlocked', None)
    
    config = load_db_config()
    app_title = config.get('APP_TITLE', 'WebScout')
    return render_template_string(MENU_TEMPLATE, userid=session.get('userid'), version=APP_VERSION, app_title=app_title)

@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    dynamic_pwd = datetime.now().strftime('%Y%m%d') + '5896'
    msg = ""
    current_max_devices = LICENSE_CACHE.get('max_devices', 5) # 取得動態上限
    
    if request.method == 'POST':
        if 'settings_pwd' in request.form:
            if request.form.get('settings_pwd') == dynamic_pwd:
                session['settings_unlocked'] = True
                return redirect(url_for('settings_page'))
            else:
                return render_template_string(SETTINGS_LOGIN_TEMPLATE, error="密碼錯誤！請輸入正確的動態密碼。")
                
        elif session.get('settings_unlocked'):
            action = request.form.get('action')
            
            # 清除所有綁定裝置
            if action == 'reset_devices':
                save_devices({})
                msg = f"✅ 所有裝置綁定已成功清除！接下來登入的前 {current_max_devices} 台裝置將會自動獲得授權。"
            
            # 儲存資料庫設定
            elif action == 'save_db':
                current_config = load_db_config()
                current_config['APP_TITLE'] = request.form.get('app_title', 'WebScout')
                current_config['SERVER'] = request.form.get('server', '')
                current_config['DATABASE'] = request.form.get('database', '')
                current_config['UID'] = request.form.get('uid', '')
                current_config['PWD_DECRYPTED'] = request.form.get('pwd', '')
                current_config['USE_WINDOWS_AUTH'] = True if request.form.get('use_windows_auth') else False
                try:
                    save_db_config(current_config)
                    msg = "✅ 連線設定已成功儲存！下次連線即生效。"
                except Exception as e:
                    msg = f"❌ 儲存失敗：{e}"

    if not session.get('settings_unlocked'):
        return render_template_string(SETTINGS_LOGIN_TEMPLATE, error=None)
        
    current_config = load_db_config()
    device_count = len(load_devices())
    return render_template_string(SETTINGS_TEMPLATE, config=current_config, msg=msg, device_count=device_count, max_devices=current_max_devices)

@app.route('/search')
def search_page():
    if not session.get('logged_in'): return redirect(url_for('login'))
    return render_template_string(HTML_TEMPLATE)

@app.route('/sales')
def sales_page():
    if not session.get('logged_in'): return redirect(url_for('login'))
    return render_template_string(SALES_TEMPLATE)

@app.route('/ship')
def ship_page():
    if not session.get('logged_in'): return redirect(url_for('login'))
    return render_template_string(SHIP_TEMPLATE)

@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    if not session.get('logged_in'): return redirect(url_for('login'))
    msg = ""
    if request.method == 'POST':
        files = request.files.getlist('images')
        manual_goodid = request.form.get('goodid', '').strip()
        
        if not files or files[0].filename == '':
            msg = "❌ 請選擇要上傳的檔案！"
        else:
            success_count = 0
            fail_count = 0
            error_msgs = []
            for file in files:
                if file and file.filename != '':
                    ext = os.path.splitext(file.filename)[1].lower()
                    if ext not in ['.jpg', '.jpeg', '.png', '.gif']:
                        fail_count += 1
                        error_msgs.append(f"{file.filename} (格式不符)")
                        continue
                    if manual_goodid and len(files) == 1:
                        filename = f"{manual_goodid}{ext}"
                    else:
                        filename = file.filename.replace('\\', '/').split('/')[-1]
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    try:
                        img = Image.open(file)
                        if img.mode in ("RGBA", "P") and ext in ['.jpg', '.jpeg']:
                            img = img.convert("RGB")
                        img = img.resize((480, 480), getattr(Image, 'Resampling', Image).LANCZOS)
                        img.save(filepath, optimize=True, quality=85)
                        success_count += 1
                    except Exception as e:
                        fail_count += 1
                        error_msgs.append(f"{file.filename} (錯誤: {e})")
            if fail_count == 0:
                msg = f"✅ 成功！共上傳並壓縮了 {success_count} 張圖片 (480x480)。"
            else:
                err_text = "<br>".join(error_msgs[:3])
                if len(error_msgs) > 3: err_text += "<br>...(還有更多)"
                msg = f"⚠️ 完成！成功: {success_count} 張，失敗: {fail_count} 張。<br>失敗詳情:<br>{err_text}"
    return render_template_string(UPLOAD_TEMPLATE, msg=msg)

@app.route('/api/image')
def serve_image():
    if not session.get('logged_in'): return "未授權，請先登入", 401
    filename = request.args.get('file', '')
    if filename:
        safe_filename = os.path.basename(filename.replace('\\', '/'))
        img_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        if os.path.exists(img_path):
            try:
                return send_file(img_path)
            except Exception as e:
                return f"圖片讀取失敗: {e}", 500
    return "找不到圖片", 404

@app.route('/api/sales')
def api_sales():
    if not session.get('logged_in'): return jsonify({'error': '連線逾時，請重新登入'}), 401
    start_date = request.args.get('start', '').replace('-', '')
    end_date = request.args.get('end', '').replace('-', '')
    
    conn = get_db_connection()
    if not conn: return jsonify({'error': '資料庫連線失敗，請檢查系統設定'})
    try:
        cursor = conn.cursor()
        sql = """
            SELECT RTRIM(LTRIM(S.sellbranch)) AS sellbranch, RTRIM(LTRIM(C.clientname)) AS branchname,
                   RTRIM(LTRIM(S.selldate)) AS selldate, RTRIM(LTRIM(S.goodid)) AS goodid,
                   RTRIM(LTRIM(G.goodname)) AS goodname, 
                   CAST(ROUND((CASE WHEN S.SellMode IN ('2', '8') THEN -1 ELSE 1 END) * (ISNULL(S.SellCash, 0) + ISNULL(S.SellCardAmount, 0) + ISNULL(S.SellGiftAmount, 0)), 0) AS INT) AS sellprice,
                   ISNULL(GS.TotalStock, 0) AS current_stock
            FROM sell S
            LEFT JOIN client C ON RTRIM(LTRIM(S.sellbranch)) = RTRIM(LTRIM(C.clientid))
            LEFT JOIN goods G ON RTRIM(LTRIM(S.goodid)) = RTRIM(LTRIM(G.GoodID))
            LEFT JOIN (
                SELECT RTRIM(LTRIM(GoodID)) AS GoodID, SUM(ISNULL(StorageTotalNum, 0)) AS TotalStock
                FROM GoodStorage
                GROUP BY RTRIM(LTRIM(GoodID))
            ) GS ON RTRIM(LTRIM(S.goodid)) = GS.GoodID
            WHERE RTRIM(LTRIM(S.selldate)) >= ? AND RTRIM(LTRIM(S.selldate)) <= ?
            ORDER BY S.selldate DESC, S.sellbranch
        """
        cursor.execute(sql, (start_date, end_date))
        cols = [c[0] for c in cursor.description]
        res = [dict(zip(cols, r)) for r in cursor.fetchall()]
        conn.close()
        
        uploaded_files = {}
        if os.path.exists(UPLOAD_FOLDER):
            for f in os.listdir(UPLOAD_FOLDER):
                name, ext = os.path.splitext(f)
                uploaded_files[name.upper().strip()] = f
                
        for r in res:
            good_id = str(r.get('goodid', '')).upper().strip()
            r['ImageFilename'] = uploaded_files.get(good_id, '')

        return jsonify(res)
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/api/ship')
def api_ship():
    if not session.get('logged_in'): return jsonify({'error': '連線逾時，請重新登入'}), 401
    start_date = request.args.get('start', '').replace('-', '')
    end_date = request.args.get('end', '').replace('-', '')
    
    conn = get_db_connection()
    if not conn: return jsonify({'error': '資料庫連線失敗，請檢查系統設定'})
    try:
        cursor = conn.cursor()
        sql = """
            SELECT RTRIM(LTRIM(H.custid)) AS custid, RTRIM(LTRIM(C.clientname)) AS custname,
                   RTRIM(LTRIM(H.shipdate)) AS shipdate, H.shipmode,
                   RTRIM(LTRIM(D.goodid)) AS goodid, RTRIM(LTRIM(G.goodname)) AS goodname,
                   CAST(ROUND(D.totalshipnum, 0) AS INT) AS detail_qty, 
                   CAST(ROUND(D.shipamount, 0) AS INT) AS detail_amount
            FROM ship H
            INNER JOIN shipdetail D ON RTRIM(LTRIM(H.shipid)) = RTRIM(LTRIM(D.shipid))
            LEFT JOIN client C ON RTRIM(LTRIM(H.custid)) = RTRIM(LTRIM(C.clientid))
            LEFT JOIN goods G ON RTRIM(LTRIM(D.goodid)) = RTRIM(LTRIM(G.GoodID))
            WHERE RTRIM(LTRIM(H.shipdate)) >= ? AND RTRIM(LTRIM(H.shipdate)) <= ?
              AND H.shipmode IN (3, 4)
            ORDER BY H.custid, H.shipdate DESC
        """
        cursor.execute(sql, (start_date, end_date))
        cols = [c[0] for c in cursor.description]
        res = [dict(zip(cols, r)) for r in cursor.fetchall()]
        conn.close()
        
        uploaded_files = {}
        if os.path.exists(UPLOAD_FOLDER):
            for f in os.listdir(UPLOAD_FOLDER):
                name, ext = os.path.splitext(f)
                uploaded_files[name.upper().strip()] = f
                
        for r in res:
            good_id = str(r.get('goodid', '')).upper().strip()
            r['ImageFilename'] = uploaded_files.get(good_id, '')

        return jsonify(res)
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/api/search')
def api():
    if not session.get('logged_in'): return jsonify({'error': '連線逾時，請重新登入'}), 401
    q = request.args.get('q', '')
    
    conn = get_db_connection()
    if not conn: return jsonify({'error': '資料庫連線失敗，請檢查系統設定'})
    try:
        cursor = conn.cursor()
        sql = """
            SELECT TOP 100 G.GoodID, G.Store, RTRIM(LTRIM(C.clientname)) AS StoreName,
                   G.StorageTotalNum, 
                   RTRIM(LTRIM(M.SizeNo1)) AS SizeNo1, RTRIM(LTRIM(M.SizeNo2)) AS SizeNo2, RTRIM(LTRIM(M.SizeNo3)) AS SizeNo3,
                   G.StorageNum01, G.StorageNum02, G.StorageNum03, G.StorageNum04, G.StorageNum05, G.StorageNum06, G.StorageNum07, G.StorageNum08, G.StorageNum09, G.StorageNum10, G.StorageNum11, G.StorageNum12, G.StorageNum13, G.StorageNum14, G.StorageNum15, G.StorageNum16, G.StorageNum17,
                   S1.Size01 AS S1_01, S1.Size02 AS S1_02, S1.Size03 AS S1_03, S1.Size04 AS S1_04, S1.Size05 AS S1_05, S1.Size06 AS S1_06, S1.Size07 AS S1_07, S1.Size08 AS S1_08, S1.Size09 AS S1_09, S1.Size10 AS S1_10, S1.Size11 AS S1_11, S1.Size12 AS S1_12, S1.Size13 AS S1_13, S1.Size14 AS S1_14, S1.Size15 AS S1_15, S1.Size16 AS S1_16, S1.Size17 AS S1_17,
                   S2.Size01 AS S2_01, S2.Size02 AS S2_02, S2.Size03 AS S2_03, S2.Size04 AS S2_04, S2.Size05 AS S2_05, S2.Size06 AS S2_06, S2.Size07 AS S2_07, S2.Size08 AS S2_08, S2.Size09 AS S2_09, S2.Size10 AS S2_10, S2.Size11 AS S2_11, S2.Size12 AS S2_12, S2.Size13 AS S2_13, S2.Size14 AS S2_14, S2.Size15 AS S2_15, S2.Size16 AS S2_16, S2.Size17 AS S2_17,
                   S3.Size01 AS S3_01, S3.Size02 AS S3_02, S3.Size03 AS S3_03, S3.Size04 AS S3_04, S3.Size05 AS S3_05, S3.Size06 AS S3_06, S3.Size07 AS S3_07, S3.Size08 AS S3_08, S3.Size09 AS S3_09, S3.Size10 AS S3_10, S3.Size11 AS S3_11, S3.Size12 AS S3_12, S3.Size13 AS S3_13, S3.Size14 AS S3_14, S3.Size15 AS S3_15, S3.Size16 AS S3_16, S3.Size17 AS S3_17
            FROM GoodStorage G
            LEFT JOIN goods M ON RTRIM(LTRIM(G.GoodID)) = RTRIM(LTRIM(M.GoodID))
            LEFT JOIN client C ON RTRIM(LTRIM(G.Store)) = RTRIM(LTRIM(C.clientid))
            LEFT JOIN Size S1 ON S1.SizeNo = NULLIF(RTRIM(LTRIM(M.SizeNo1)), '')
            LEFT JOIN Size S2 ON S2.SizeNo = NULLIF(RTRIM(LTRIM(M.SizeNo2)), '')
            LEFT JOIN Size S3 ON S3.SizeNo = NULLIF(RTRIM(LTRIM(M.SizeNo3)), '')
            WHERE G.GoodID LIKE ? 
            ORDER BY G.GoodID, G.Store
        """
        cursor.execute(sql, f"%{q}%")
        cols = [c[0] for c in cursor.description]
        res = [dict(zip(cols, r)) for r in cursor.fetchall()]
        conn.close()
        
        uploaded_files = {}
        if os.path.exists(UPLOAD_FOLDER):
            for f in os.listdir(UPLOAD_FOLDER):
                name, ext = os.path.splitext(f)
                uploaded_files[name.upper().strip()] = f
                
        for r in res:
            good_id = str(r.get('GoodID', '')).upper().strip()
            r['ImageFilename'] = uploaded_files.get(good_id, '')

        return jsonify(res)
    except Exception as e: return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("🚀 伺服器啟動成功： http://localhost:5888")
    from waitress import serve
    serve(app, host='0.0.0.0', port=5888)