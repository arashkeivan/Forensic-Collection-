#!/data/data/com.termux/files/usr/bin/python3
# forensic_evidence_collector.py
# جمع‌آوری مدارک قانونی از دستگاه Android

import os
import sys
import json
import hashlib
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

class ForensicEvidenceCollector:
    def __init__(self, case_number="CASE_" + datetime.now().strftime("%Y%m%d")):
        self.case_number = case_number
        self.evidence_dir = f"forensic_evidence_{case_number}"
        self.log_file = os.path.join(self.evidence_dir, "collection_log.txt")
        
        # ایجاد دایرکتوری‌های لازم
        self.setup_directories()
        
    def setup_directories(self):
        """ایجاد ساختار دایرکتوری برای مدارک"""
        dirs = [
            self.evidence_dir,
            os.path.join(self.evidence_dir, "system_info"),
            os.path.join(self.evidence_dir, "installed_apps"),
            os.path.join(self.evidence_dir, "network_info"),
            os.path.join(self.evidence_dir, "suspicious_files"),
            os.path.join(self.evidence_dir, "timeline"),
            os.path.join(self.evidence_dir, "logs"),
            os.path.join(self.evidence_dir, "hash_analysis")
        ]
        
        for d in dirs:
            os.makedirs(d, exist_ok=True)
    
    def log_event(self, event, details=""):
        """ثبت رویداد در لاگ"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}"
        if details:
            log_entry += f" - {details}"
        
        print(log_entry)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + "\n")
    
    def calculate_hash(self, filepath):
        """محاسبه هش فایل"""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return "ERROR"
    
    def collect_system_information(self):
        """جمع‌آوری اطلاعات سیستم"""
        self.log_event("جمع‌آوری اطلاعات سیستم")
        
        system_info = {
            "collection_time": datetime.now().isoformat(),
            "case_number": self.case_number,
            "device_info": {},
            "user_info": {}
        }
        
        # اطلاعات دستگاه
        commands = {
            "device_model": "getprop ro.product.model",
            "manufacturer": "getprop ro.product.manufacturer",
            "android_version": "getprop ro.build.version.release",
            "build_number": "getprop ro.build.display.id",
            "build_date": "getprop ro.build.date",
            "security_patch": "getprop ro.build.version.security_patch",
            "serial_number": "getprop ro.serialno",
            "imei": "service call iphonesubinfo 1 | cut -d \"'\" -f2",
            "root_status": "which su && echo 'ROOTED' || echo 'NOT_ROOTED'"
        }
        
        for key, cmd in commands.items():
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                system_info["device_info"][key] = result.stdout.strip()
            except:
                system_info["device_info"][key] = "ERROR"
        
        # ذخیره اطلاعات سیستم
        sysinfo_file = os.path.join(self.evidence_dir, "system_info", "system_details.json")
        with open(sysinfo_file, 'w', encoding='utf-8') as f:
            json.dump(system_info, f, indent=2, ensure_ascii=False)
        
        self.log_event("اطلاعات سیستم ذخیره شد", sysinfo_file)
        return system_info
    
    def collect_installed_apps(self):
        """جمع‌آوری اطلاعات برنامه‌های نصب شده"""
        self.log_event("جمع‌آوری اطلاعات برنامه‌های نصب شده")
        
        apps_data = []
        
        try:
            # دریافت لیست تمام برنامه‌ها
            cmd = "pm list packages -f -i -u"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if line.startswith('package:'):
                    parts = line.replace('package:', '').strip().split('=')
                    if len(parts) >= 3:
                        apk_path = parts[0]
                        package_name = parts[1]
                        installer = parts[2] if len(parts) > 2 else "unknown"
                        
                        # دریافت اطلاعات بیشتر
                        app_info = {
                            "package": package_name,
                            "apk_path": apk_path,
                            "installer": installer,
                            "install_date": self.get_app_install_date(package_name),
                            "permissions": self.get_app_permissions(package_name),
                            "version": self.get_app_version(package_name)
                        }
                        
                        # محاسبه هش APK
                        if os.path.exists(apk_path):
                            app_info["sha256"] = self.calculate_hash(apk_path)
                        
                        apps_data.append(app_info)
            
            # ذخیره اطلاعات برنامه‌ها
            apps_file = os.path.join(self.evidence_dir, "installed_apps", "all_applications.json")
            with open(apps_file, 'w', encoding='utf-8') as f:
                json.dump(apps_data, f, indent=2, ensure_ascii=False)
            
            # ایجاد لیست CSV برای گزارش
            self.create_apps_csv(apps_data)
            
            self.log_event(f"{len(apps_data)} برنامه ثبت شد", apps_file)
            
        except Exception as e:
            self.log_event("خطا در جمع‌آوری برنامه‌ها", str(e))
        
        return apps_data
    
    def get_app_install_date(self, package_name):
        """دریافت تاریخ نصب برنامه"""
        try:
            cmd = f"dumpsys package {package_name} | grep firstInstallTime"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                timestamp = result.stdout.split('=')[-1].strip()
                if timestamp.isdigit():
                    dt = datetime.fromtimestamp(int(timestamp)/1000)
                    return dt.isoformat()
        except:
            pass
        return "UNKNOWN"
    
    def get_app_permissions(self, package_name):
        """دریافت مجوزهای برنامه"""
        try:
            cmd = f"dumpsys package {package_name} | grep -A50 'requested permissions:'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            permissions = []
            for line in result.stdout.split('\n'):
                if 'android.permission' in line:
                    perm = line.strip()
                    if perm and ':' not in perm:
                        permissions.append(perm)
            return permissions[:20]  # فقط 20 مجوز اول
        except:
            return []
    
    def get_app_version(self, package_name):
        """دریافت نسخه برنامه"""
        try:
            cmd = f"dumpsys package {package_name} | grep versionName"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                return result.stdout.split('=')[-1].strip()
        except:
            pass
        return "UNKNOWN"
    
    def create_apps_csv(self, apps_data):
        """ایجاد فایل CSV از برنامه‌ها"""
        csv_file = os.path.join(self.evidence_dir, "installed_apps", "applications.csv")
        
        header = "Package Name,APK Path,Installer,Install Date,Version,SHA256\n"
        
        with open(csv_file, 'w', encoding='utf-8') as f:
            f.write(header)
            for app in apps_data:
                line = f'"{app["package"]}","{app["apk_path"]}","{app["installer"]}",'
                line += f'"{app.get("install_date", "")}","{app.get("version", "")}",'
                line += f'"{app.get("sha256", "")}"\n'
                f.write(line)
        
        self.log_event("فایل CSV برنامه‌ها ایجاد شد", csv_file)
    
    def collect_network_information(self):
        """جمع‌آوری اطلاعات شبکه"""
        self.log_event("جمع‌آوری اطلاعات شبکه")
        
        network_info = {
            "wifi_info": {},
            "dns_info": {},
            "connections": [],
            "routing": {}
        }
        
        # اطلاعات WiFi
        try:
            wifi_cmd = "dumpsys wifi | grep -A20 'Current Configuration'"
            result = subprocess.run(wifi_cmd, shell=True, capture_output=True, text=True)
            network_info["wifi_info"]["current_config"] = result.stdout[:2000]
        except:
            pass
        
        # DNS سرورها
        try:
            dns_cmd = "getprop | grep dns"
            result = subprocess.run(dns_cmd, shell=True, capture_output=True, text=True)
            network_info["dns_info"] = result.stdout
        except:
            pass
        
        # اتصالات شبکه
        try:
            conn_cmd = "netstat -tuna 2>/dev/null || ss -tuna 2>/dev/null"
            result = subprocess.run(conn_cmd, shell=True, capture_output=True, text=True)
            network_info["connections"] = result.stdout.split('\n')[:100]
        except:
            pass
        
        # Routing
        try:
            route_cmd = "ip route show"
            result = subprocess.run(route_cmd, shell=True, capture_output=True, text=True)
            network_info["routing"] = result.stdout
        except:
            pass
        
        # ذخیره اطلاعات شبکه
        net_file = os.path.join(self.evidence_dir, "network_info", "network_data.json")
        with open(net_file, 'w', encoding='utf-8') as f:
            json.dump(network_info, f, indent=2, ensure_ascii=False)
        
        self.log_event("اطلاعات شبکه ذخیره شد", net_file)
        return network_info
    
    def scan_suspicious_files(self):
        """اسکن فایل‌های مشکوک"""
        self.log_event("اسکن فایل‌های مشکوک")
        
        suspicious_locations = [
            "/data/local/tmp",
            "/data/app",
            "/system/app",
            "/system/priv-app",
            "/sdcard/Download",
            "/sdcard/Android/data",
            "/data/data/com.termux/files/home"
        ]
        
        suspicious_patterns = [
            "*.apk", "*.dex", "*.so", "*.sh", "*.py",
            "hack", "crack", "spy", "sniffer", "keylog",
            "backdoor", "trojan", "malware", "inject"
        ]
        
        findings = []
        
        for location in suspicious_locations:
            if os.path.exists(location):
                for pattern in suspicious_patterns:
                    try:
                        find_cmd = f"find '{location}' -type f -iname '{pattern}' 2>/dev/null"
                        result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
                        
                        for filepath in result.stdout.split('\n'):
                            if filepath.strip():
                                file_info = self.analyze_suspicious_file(filepath.strip())
                                if file_info:
                                    findings.append(file_info)
                    except:
                        pass
        
        # ذخیره یافته‌های مشکوک
        if findings:
            suspicious_file = os.path.join(self.evidence_dir, "suspicious_files", "suspicious_findings.json")
            with open(suspicious_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)
            
            self.log_event(f"{len(findings)} فایل مشکوک یافت شد", suspicious_file)
        
        return findings
    
    def analyze_suspicious_file(self, filepath):
        """تحلیل فایل مشکوک"""
        try:
            stat = os.stat(filepath)
            file_info = {
                "path": filepath,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "sha256": self.calculate_hash(filepath),
                "permissions": oct(stat.st_mode)[-3:]
            }
            
            # بررسی محتوا (اولین 1000 بایت)
            try:
                with open(filepath, 'rb') as f:
                    content_preview = f.read(1000)
                    # بررسی stringهای قابل خواندن
                    strings = []
                    for i in range(0, len(content_preview), 4):
                        chunk = content_preview[i:i+4]
                        try:
                            text = chunk.decode('utf-8', errors='ignore')
                            if any(keyword in text.lower() for keyword in ['http', 'url', 'ip', 'password', 'key']):
                                strings.append(text.strip())
                        except:
                            pass
                    
                    if strings:
                        file_info["suspicious_strings"] = strings[:10]
            except:
                pass
            
            return file_info
        except:
            return None
    
    def create_timeline_analysis(self):
        """ایجاد تایم‌لاین زمانی از رویدادها"""
        self.log_event("ایجاد تایم‌لاین زمانی")
        
        timeline = []
        
        # اسکن فایل‌های مهم برای تاریخ‌های تغییرات
        important_files = [
            "/data/system/packages.xml",  # اطلاعات نصب برنامه‌ها
            "/data/system/users/0/runtime-permissions.xml",  # مجوزها
            "/data/misc/wifi/wpa_supplicant.conf",  # تنظیمات WiFi
            "/data/system/dropbox/",  # لاگ‌های سیستم
        ]
        
        for filepath in important_files:
            if os.path.exists(filepath):
                if os.path.isdir(filepath):
                    # برای دایرکتوری‌ها، فایل‌های داخل را بررسی کنیم
                    try:
                        for root, dirs, files in os.walk(filepath):
                            for file in files[:20]:  # فقط 20 فایل اول
                                full_path = os.path.join(root, file)
                                stat = os.stat(full_path)
                                timeline.append({
                                    "timestamp": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                    "event": f"FILE_MODIFIED",
                                    "path": full_path,
                                    "size": stat.st_size
                                })
                    except:
                        pass
                else:
                    # برای فایل‌های معمولی
                    stat = os.stat(filepath)
                    timeline.append({
                        "timestamp": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "event": "FILE_MODIFIED",
                        "path": filepath,
                        "size": stat.st_size
                    })
        
        # مرتب‌سازی بر اساس زمان
        timeline.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # ذخیره تایم‌لاین
        timeline_file = os.path.join(self.evidence_dir, "timeline", "system_timeline.json")
        with open(timeline_file, 'w', encoding='utf-8') as f:
            json.dump(timeline[:100], f, indent=2, ensure_ascii=False)  # فقط 100 مورد آخر
        
        self.log_event("تایم‌لاین ایجاد شد", timeline_file)
        return timeline
    
    def collect_system_logs(self):
        """جمع‌آوری لاگ‌های سیستم"""
        self.log_event("جمع‌آوری لاگ‌های سیستم")
        
        logs_dir = os.path.join(self.evidence_dir, "logs")
        
        log_sources = [
            ("dmesg", "dmesg"),
            ("logcat_main", "logcat -d -b main"),
            ("logcat_system", "logcat -d -b system"),
            ("logcat_events", "logcat -d -b events"),
            ("process_list", "ps -A"),
            ("battery_stats", "dumpsys batterystats"),
            ("activity_history", "dumpsys activity activities")
        ]
        
        for log_name, command in log_sources:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
                log_file = os.path.join(logs_dir, f"{log_name}.log")
                
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(result.stdout[:100000])  # محدود کردن حجم
                
                self.log_event(f"لاگ {log_name} ذخیره شد", log_file)
            except Exception as e:
                self.log_event(f"خطا در جمع‌آوری {log_name}", str(e))
    
    def generate_summary_report(self):
        """تولید گزارش خلاصه"""
        self.log_event("تولید گزارش خلاصه")
        
        summary = {
            "case_number": self.case_number,
            "collection_time": datetime.now().isoformat(),
            "device_identified": False,
            "evidence_summary": {},
            "findings": [],
            "recommendations": []
        }
        
        # جمع‌آوری اطلاعات خلاصه
        try:
            # اطلاعات سیستم
            sysinfo_file = os.path.join(self.evidence_dir, "system_info", "system_details.json")
            with open(sysinfo_file, 'r', encoding='utf-8') as f:
                system_data = json.load(f)
                summary["device_info"] = system_data.get("device_info", {})
                summary["device_identified"] = True
        except:
            pass
        
        # بررسی فایل‌های مشکوک
        suspicious_file = os.path.join(self.evidence_dir, "suspicious_files", "suspicious_findings.json")
        if os.path.exists(suspicious_file):
            with open(suspicious_file, 'r', encoding='utf-8') as f:
                suspicious_data = json.load(f)
                summary["findings"].append(f"تعداد فایل‌های مشکوک: {len(suspicious_data)}")
        
        # توصیه‌ها
        summary["recommendations"] = [
            "تمام مدارک جمع‌آوری شده را به مراجع قانونی ارائه دهید",
            "از دستگاه فعلی برای فعالیت‌های حساس استفاده نکنید",
            "گزارش کاملی از توالی رویدادها تهیه کنید",
            "از متخصص امنیت سایبری برای تحلیل عمیق‌تر کمک بگیرید",
            "تمام ارتباطات مشکوک را مستند کنید"
        ]
        
        # ذخیره گزارش خلاصه
        summary_file = os.path.join(self.evidence_dir, "case_summary.json")
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # ایجاد گزارش متنی
        self.create_text_report(summary)
        
        self.log_event("گزارش خلاصه ایجاد شد", summary_file)
        return summary
    
    def create_text_report(self, summary):
        """ایجاد گزارش متنی برای چاپ"""
        report_file = os.path.join(self.evidence_dir, "legal_report.txt")
        
        report = f"""
        =================================================================
                        گزارش رسمی جمع‌آوری مدارک دیجیتال
        =================================================================
        
        شماره پرونده: {summary.get('case_number', 'نامشخص')}
        تاریخ و زمان: {summary.get('collection_time', 'نامشخص')}
        
        ۱. اطلاعات دستگاه:
           -------------------------------
        """
        
        if summary.get("device_info"):
            for key, value in summary["device_info"].items():
                report += f"   {key}: {value}\n"
        
        report += f"""
        
        ۲. یافته‌ها:
           -------------------------------
        """
        
        for finding in summary.get("findings", []):
            report += f"   • {finding}\n"
        
        report += f"""
        
        ۳. توصیه‌های فنی:
           -------------------------------
        """
        
        for i, rec in enumerate(summary.get("recommendations", []), 1):
            report += f"   {i}. {rec}\n"
        
        report += f"""
        
        ۴. مدارک پیوست:
           -------------------------------
           تمامی فایل‌های جمع‌آوری شده در پوشه {self.evidence_dir} ذخیره شده‌اند.
           
           این مدارک شامل:
           - اطلاعات کامل سیستم
           - لیست برنامه‌های نصب شده
           - اطلاعات شبکه و اتصالات
           - فایل‌های مشکوک با هش SHA256
           - تایم‌لاین رویدادها
           - لاگ‌های سیستم
        
        =================================================================
        توجه: این گزارش به صورت خودکار تولید شده و باید توسط کارشناس
              رسمی پزشکی قانونی یا امنیت سایبری تأیید شود.
        =================================================================
        """
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.log_event("گزارش متنی ایجاد شد", report_file)
    
    def create_evidence_package(self):
        """ایجاد بسته مدارک فشرده"""
        self.log_event("ایجاد بسته فشرده مدارک")
        
        import zipfile
        
        zip_filename = f"{self.evidence_dir}.zip"
        
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.evidence_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    arcname = os.path.relpath(filepath, self.evidence_dir)
                    zipf.write(filepath, arcname)
        
        # محاسبه هش بسته
        package_hash = self.calculate_hash(zip_filename)
        
        # ایجاد فایل تأیید
        verification_file = f"{self.evidence_dir}_verification.txt"
        with open(verification_file, 'w', encoding='utf-8') as f:
            f.write(f"Evidence Package Verification\n")
            f.write(f"=============================\n")
            f.write(f"Case Number: {self.case_number}\n")
            f.write(f"Package File: {zip_filename}\n")
            f.write(f"SHA256 Hash: {package_hash}\n")
            f.write(f"Created: {datetime.now().isoformat()}\n")
            f.write(f"\nTo verify integrity:\n")
            f.write(f"sha256sum {zip_filename}\n")
        
        self.log_event("بسته مدارک ایجاد شد", f"{zip_filename} (Hash: {package_hash[:16]}...)")
        
        return {
            "package_file": zip_filename,
            "sha256": package_hash,
            "verification_file": verification_file
        }
    
    def run_full_collection(self):
        """اجرای کامل جمع‌آوری مدارک"""
        print("=" * 70)
        print("جمع‌آوری مدارک دیجیتال برای ارائه به مراجع قانونی")
        print("=" * 70)
        
        try:
            # 1. اطلاعات سیستم
            self.collect_system_information()
            
            # 2. برنامه‌های نصب شده
            self.collect_installed_apps()
            
            # 3. اطلاعات شبکه
            self.collect_network_information()
            
            # 4. اسکن فایل‌های مشکوک
            self.scan_suspicious_files()
            
            # 5. تایم‌لاین
            self.create_timeline_analysis()
            
            # 6. لاگ‌های سیستم
            self.collect_system_logs()
            
            # 7. گزارش خلاصه
            summary = self.generate_summary_report()
            
            # 8. ایجاد بسته
            package_info = self.create_evidence_package()
            
            # نمایش نتایج
            print("\n✅ جمع‌آوری مدارک کامل شد!")
            print(f"\n📁 مدارک در پوشه: {self.evidence_dir}")
            print(f"📦 بسته فشرده: {package_info['package_file']}")
            print(f"🔐 هش تأیید: {package_info['sha256'][:32]}...")
            print(f"📄 فایل تأیید: {package_info['verification_file']}")
            
            print("\n⚠️  اقدامات مهم:")
            print("   1. بسته فشرده را در چند محل امن ذخیره کنید")
            print("   2. هش SHA256 را یادداشت کرده و با مراجع قانونی تأیید کنید")
            print("   3. از دستگاه فعلی برای ارتباطات مهم استفاده نکنید")
            print("   4. گزارش متنی را چاپ کرده و امضا کنید")
            
            return True
            
        except Exception as e:
            self.log_event("خطا در جمع‌آوری مدارک", str(e))
            print(f"❌ خطا: {e}")
            return False

# اجرای اصلی
if __name__ == "__main__":
    print("⚠️  هشدار: این اسکریپت برای جمع‌آوری مدارک قانونی است.")
    print("   قبل از اجرا از مهم بودن اطلاعات خود پشتیبان بگیرید.")
    
    # درخواست شماره پرونده
    case_num = input("شماره پرونده/شناسه را وارد کنید (یا Enter برای تاریخ): ").strip()
    if not case_num:
        case_num = "CASE_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # تأیید کاربر
    confirm = input(f"\nآیا مطمئن هستید می‌خواهید مدارک برای پرونده '{case_num}' جمع‌آوری کنید؟ (y/N): ")
    
    if confirm.lower() == 'y':
        collector = ForensicEvidenceCollector(case_num)
        collector.run_full_collection()
    else:
        print("❌ عملیات لغو شد.")
