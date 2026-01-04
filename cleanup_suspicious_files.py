#!/data/data/com.termux/files/usr/bin/python3
# cleanup_suspicious_files.py
# حذف فایل‌های مشکوک (با قابلیت بازگردانی)

import os
import json
import shutil
from datetime import datetime

class SuspiciousFileCleaner:
    def __init__(self):
        self.quarantine_dir = "quarantine_" + datetime.now().strftime("%Y%m%d")
        self.log_file = "cleanup_log.json"
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # لیست الگوهای فایل‌های مشکوک
        self.suspicious_patterns = [
            "*.vxd", "*.dll", "*.exe", "*.bat", "*.cmd",
            "*hack*", "*crack*", "*keylog*", "*spy*",
            "*sniffer*", "*inject*", "*backdoor*", "*trojan*"
        ]
        
        # مکان‌های مشکوک
        self.suspicious_locations = [
            "/data/local/tmp",
            "/sdcard/Download",
            "/sdcard/Android/data",
            "/data/data/com.termux/files/home"
        ]
    
    def scan_and_quarantine(self):
        """اسکن و قرنطینه فایل‌های مشکوک"""
        print("🔍 در حال اسکن فایل‌های مشکوک...")
        
        findings = []
        
        for location in self.suspicious_locations:
            if os.path.exists(location):
                print(f"   📁 بررسی: {location}")
                
                for pattern in self.suspicious_patterns:
                    try:
                        # جستجوی فایل‌ها
                        for root, dirs, files in os.walk(location):
                            for file in files:
                                if self.matches_pattern(file, pattern):
                                    full_path = os.path.join(root, file)
                                    file_info = self.quarantine_file(full_path)
                                    if file_info:
                                        findings.append(file_info)
                    except:
                        continue
        
        # ذخیره لاگ
        self.save_log(findings)
        
        print(f"\n📊 نتایج:")
        print(f"   فایل‌های قرنطینه شده: {len(findings)}")
        print(f"   محل قرنطینه: {self.quarantine_dir}")
        
        if findings:
            print("\n⚠️  فایل‌های مشکوک شناسایی و قرنطینه شدند.")
            print("   برای بازگردانی از لاگ فایل استفاده کنید.")
        else:
            print("\n✅ هیچ فایل مشکوکی یافت نشد.")
        
        return findings
    
    def matches_pattern(self, filename, pattern):
        """بررسی تطابق الگو"""
        import fnmatch
        return fnmatch.fnmatch(filename.lower(), pattern.lower())
    
    def quarantine_file(self, filepath):
        """قرنطینه فایل"""
        try:
            # اطلاعات فایل
            stat = os.stat(filepath)
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # نام جدید برای قرنطینه
            new_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, new_name)
            
            # کپی به قرنطینه
            shutil.copy2(filepath, quarantine_path)
            
            # حذف فایل اصلی
            os.remove(filepath)
            
            file_info = {
                "original_path": filepath,
                "quarantine_path": quarantine_path,
                "filename": filename,
                "size": stat.st_size,
                "removed_time": datetime.now().isoformat(),
                "sha256": self.calculate_hash(quarantine_path) if os.path.exists(quarantine_path) else "ERROR"
            }
            
            print(f"   ⚠️  قرنطینه: {filename}")
            return file_info
            
        except Exception as e:
            print(f"   ❌ خطا در قرنطینه {filepath}: {e}")
            return None
    
    def calculate_hash(self, filepath):
        """محاسبه هش فایل"""
        import hashlib
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return "ERROR"
    
    def save_log(self, findings):
        """ذخیره لاگ عملیات"""
        log_data = {
            "cleanup_time": datetime.now().isoformat(),
            "quarantine_dir": self.quarantine_dir,
            "total_files": len(findings),
            "files": findings
        }
        
        with open(self.log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        print(f"📝 لاگ عملیات در {self.log_file} ذخیره شد.")
    
    def restore_from_log(self, log_file=None):
        """بازگردانی فایل‌ها از لاگ"""
        if log_file is None:
            log_file = self.log_file
        
        if not os.path.exists(log_file):
            print(f"❌ فایل لاگ {log_file} یافت نشد.")
            return False
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
            
            print(f"📖 خواندن لاگ: {log_file}")
            
            restored = 0
            errors = 0
            
            for file_info in log_data.get("files", []):
                try:
                    # بررسی وجود فایل در قرنطینه
                    if os.path.exists(file_info["quarantine_path"]):
                        # بازگردانی به محل اصلی
                        shutil.copy2(file_info["quarantine_path"], file_info["original_path"])
                        print(f"   ✅ بازگردانی: {file_info['filename']}")
                        restored += 1
                    else:
                        print(f"   ❌ فایل در قرنطینه یافت نشد: {file_info['filename']}")
                        errors += 1
                        
                except Exception as e:
                    print(f"   ❌ خطا در بازگردانی {file_info['filename']}: {e}")
                    errors += 1
            
            print(f"\n📊 نتایج بازگردانی:")
            print(f"   ✅ موفق: {restored}")
            print(f"   ❌ خطا: {errors}")
            
            return True
            
        except Exception as e:
            print(f"❌ خطا در خواندن لاگ: {e}")
            return False

# رابط کاربری ساده
def main():
    print("=" * 60)
    print("پاکسازی فایل‌های مشکوک")
    print("=" * 60)
    print("\nگزینه‌ها:")
    print("  1. اسکن و قرنطینه فایل‌های مشکوک")
    print("  2. بازگردانی فایل‌ها از لاگ")
    print("  3. خروج")
    
    choice = input("\nانتخاب شما (1-3): ").strip()
    
    cleaner = SuspiciousFileCleaner()
    
    if choice == "1":
        print("\n⚠️  هشدار: این عملیات فایل‌های مشکوک را حذف می‌کند.")
        confirm = input("آیا مطمئن هستید؟ (y/N): ")
        
        if confirm.lower() == 'y':
            cleaner.scan_and_quarantine()
        else:
            print("❌ عملیات لغو شد.")
    
    elif choice == "2":
        log_file = input("آدرس فایل لاگ (Enter برای لاگ پیش‌فرض): ").strip()
        if not log_file:
            log_file = None
        
        cleaner.restore_from_log(log_file)
    
    elif choice == "3":
        print("👋 خروج...")
    
    else:
        print("❌ انتخاب نامعتبر.")

if __name__ == "__main__":
    main()
