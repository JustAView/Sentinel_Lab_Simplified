#!/usr/bin/env python3
"""Sentinel Lab local server. Scans only ./lab_files and never executes files."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import hashlib, json, os, shutil, time, datetime, urllib.parse

ROOT = Path(__file__).resolve().parent
LAB = ROOT / "lab_files"
QUARANTINE = ROOT / "quarantine"
REPORTS = ROOT / "reports"
for p in (LAB, QUARANTINE, REPORTS):
    p.mkdir(exist_ok=True)

# Harmless demo signatures. These are textual indicators only, not malware execution.
TEXT_SIGNATURES = [
    (b"SENTINEL_DEMO_SUSPICIOUS", "Учебный маркер подозрительного содержимого"),
    (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "Тестовая сигнатура EICAR (учебная строка)"),
    (b"powershell -enc", "Подозрительная командная строка PowerShell"),
    (b"CreateRemoteThread", "Индикатор потенциально опасного API"),
    (b"autorun.inf", "Упоминание автозапуска"),
]
SUSPICIOUS_EXTENSIONS = {".scr", ".pif", ".vbs", ".js", ".hta", ".bat", ".cmd", ".ps1"}
MAX_FILE_SIZE = 20 * 1024 * 1024

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def scan_file(path):
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            return {"status":"needs_review", "reason":"Файл больше лимита проверки 20 МБ", "size":size, "sha256":None}
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        for sig, reason in TEXT_SIGNATURES:
            if sig.lower() in data.lower():
                return {"status":"detected", "reason":reason, "size":size, "sha256":digest}
        if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
            return {"status":"needs_review", "reason":"Тип файла требует ручной проверки; это не подтверждение заражения", "size":size, "sha256":digest}
        return {"status":"clean", "reason":"Учебные сигнатуры не обнаружены", "size":size, "sha256":digest}
    except Exception as e:
        return {"status":"error", "reason":"Не удалось прочитать файл: " + str(e), "size":0, "sha256":None}

def metadata(path, base):
    try:
        rel = str(path.relative_to(base)).replace("\\", "/")
        st = path.stat()
        return {"name":path.name, "path":rel, "size":st.st_size, "modified":datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")}
    except Exception:
        return {"name":path.name, "path":path.name, "size":0, "modified":""}

def get_files(folder, folder_name):
    items = []
    for p in sorted(folder.rglob("*")):
        if p.is_file() and not p.is_symlink():
            item = metadata(p, folder)
            item["folder"] = folder_name
            if folder_name == "lab_files":
                item.update(scan_file(p))
            else:
                try:
                    data = p.read_bytes()[:4096]
                except Exception:
                    data = b""
                if data.startswith(b"SENTINEL_NEUTRALIZED\n"):
                    item.update({"status":"neutralized", "reason":"Содержимое заменено безопасной заглушкой", "sha256":hashlib.sha256(data).hexdigest()})
                else:
                    item.update({"status":"quarantine", "reason":"Изолирован пользователем", "sha256":hashlib.sha256(data).hexdigest() if data else None})
            items.append(item)
    return items

def save_report(payload):
    REPORTS.mkdir(exist_ok=True)
    name = "scan-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".json"
    out = REPORTS / name
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return name

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)
    def log_message(self, fmt, *args):
        print("[Sentinel] " + (fmt % args))
    def send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except Exception:
            return {}
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/files":
            self.send_json({"files":get_files(LAB,"lab_files"), "quarantine":get_files(QUARANTINE,"quarantine")})
        elif parsed.path == "/api/health":
            self.send_json({"ok":True,"root":str(ROOT),"lab_folder":"lab_files"})
        elif parsed.path == "/api/reports":
            reports = []
            for p in sorted(REPORTS.glob("*.json"), reverse=True):
                try: reports.append({"name":p.name,"data":json.loads(p.read_text(encoding="utf-8"))})
                except Exception: pass
            self.send_json({"reports":reports})
        else:
            super().do_GET()
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        body = self.read_json()
        if parsed.path == "/api/scan":
            files = get_files(LAB,"lab_files")
            findings = [f for f in files if f["status"] in ("detected","needs_review","error")]
            report = {"project":"Sentinel Lab","generated_at":datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                      "scope":"Только файлы в папке lab_files; исполняемые файлы не запускаются.",
                      "files_scanned":len(files),"detections":sum(f["status"]=="detected" for f in files),
                      "needs_review":sum(f["status"]=="needs_review" for f in files),
                      "clean":sum(f["status"]=="clean" for f in files),"findings":findings,"files":files}
            report["report_file"] = save_report(report)
            self.send_json(report)
        elif parsed.path == "/api/quarantine":
            rel = body.get("path","")
            src = (LAB / rel).resolve()
            if not rel or not src.is_relative_to(LAB.resolve()) or not src.is_file() or src.is_symlink():
                self.send_json({"error":"Недопустимый путь. Можно изолировать только файл из lab_files."},400); return
            target = QUARANTINE / (hashlib.sha256((str(src) + str(time.time_ns())).encode()).hexdigest()[:8] + "__" + src.name)
            try:
                shutil.move(str(src),str(target))
                self.send_json({"ok":True,"message":"Файл перемещён в локальный карантин.","files":get_files(LAB,"lab_files"),"quarantine":get_files(QUARANTINE,"quarantine")})
            except Exception as e: self.send_json({"error":str(e)},500)
        elif parsed.path == "/api/neutralize":
            name = body.get("name", "")
            src = (QUARANTINE / name).resolve()
            if not name or not src.is_relative_to(QUARANTINE.resolve()) or not src.is_file() or src.is_symlink():
                self.send_json({"error":"Недопустимый объект карантина."},400); return
            try:
                src.write_text("SENTINEL_NEUTRALIZED\nЭтот объект обезврежен в учебном стенде. Исходное содержимое заменено.\n", encoding="utf-8")
                self.send_json({"ok":True,"message":"Содержимое заменено безопасной текстовой заглушкой.","quarantine":get_files(QUARANTINE,"quarantine")})
            except Exception as e: self.send_json({"error":str(e)},500)
        elif parsed.path == "/api/delete":
            name = body.get("name", "")
            src = (QUARANTINE / name).resolve()
            if not name or not src.is_relative_to(QUARANTINE.resolve()) or not src.is_file() or src.is_symlink():
                self.send_json({"error":"Недопустимый объект карантина."},400); return
            try:
                src.unlink()
                self.send_json({"ok":True,"message":"Файл удалён из карантина.","quarantine":get_files(QUARANTINE,"quarantine")})
            except Exception as e: self.send_json({"error":str(e)},500)
        elif parsed.path == "/api/restore":
            name = body.get("name","")
            src = (QUARANTINE / name).resolve()
            if not name or not src.is_relative_to(QUARANTINE.resolve()) or not src.is_file() or src.is_symlink():
                self.send_json({"error":"Недопустимый объект карантина."},400); return
            original = name.split("__", 1)[1] if "__" in name else name
            target = LAB / original
            if target.exists():
                target = LAB / (original + ".restored")
            try:
                shutil.move(str(src),str(target))
                self.send_json({"ok":True,"message":"Файл восстановлен в lab_files.","files":get_files(LAB,"lab_files"),"quarantine":get_files(QUARANTINE,"quarantine")})
            except Exception as e: self.send_json({"error":str(e)},500)
        elif parsed.path == "/api/create-demo":
            name = str(body.get("name","demo-note.txt")).strip()
            # Only permit a plain basename; never write outside the lab folder.
            if not name or Path(name).name != name or name in (".","..") or len(name)>100:
                self.send_json({"error":"Укажите имя файла без пути."},400); return
            if not Path(name).suffix: name += ".txt"
            content = str(body.get("content","SENTINEL_DEMO_SUSPICIOUS\nУчебный маркер для проверки сканером.\n"))[:10000]
            target = LAB / name
            if target.exists():
                self.send_json({"error":"Файл с таким именем уже существует."},409); return
            target.write_text(content,encoding="utf-8")
            self.send_json({"ok":True,"file":metadata(target,LAB)})
        else:
            self.send_json({"error":"Неизвестный API endpoint"},404)

if __name__ == "__main__":
    print("Sentinel Lab запущен: http://127.0.0.1:8765")
    print("Сканируются только файлы внутри папки lab_files. Не запускайте неизвестные файлы.")
    try:
        ThreadingHTTPServer(("127.0.0.1",8765),Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nSentinel Lab остановлен.")
