#!/data/data/com.termux/files/usr/bin/python3
# realtime_monitor.py
# مانیتورینگ بلادرنگ فعالیت‌های سیستم

import time
import json
from datetime import datetime
import subprocess
import threading

class RealTimeMonitor:
    def __init__(self, monitoring_duration=300):  # 5 دقیقه پیش‌فرض
        self.monitoring_duration = monitoring_duration
        self.log_file = f"realtime_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.running = True
        self.events = []
        
    def monitor_network_connections(self):
        """مانیتورینگ اتصالات شبکه"""
        print("🔌 مانیتورینگ اتصالات شبکه...")
        
        while self.running:
            try:
                # دریافت اتصالات فعال
                cmd = "netstat -tuna 2>/dev/null || ss -tuna 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                connections = []
                for line in result.stdout.split('\n'):
                    if any(x in line for x in ['ESTAB', 'LISTEN', 'TIME_WAIT']):
                        connections.append(line.strip())
                
                if connections:
                    event = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "NETWORK_CONNECTIONS",
                        "count": len(connections),
                        "sample": connections[:5]  # فقط 5 نمونه
                    }
                    self.events.append(event)
                    self.log_event(event)
                
                time.sleep(10)  # هر 10 ثانیه
                
            except Exception as e:
                print(f"خطا در مانیتورینگ شبکه: {e}")
                time.sleep(5)
    
    def monitor_dns_requests(self):
        """مانیتورینگ درخواست‌های DNS"""
        print("🌐 مانیتورینگ درخواست‌های DNS...")
        
        # این بخش نیاز به دسترسی root دارد
        try:
            root_check = subprocess.run("su -c 'echo test'", shell=True, 
                                       capture_output=True, text=True)
            if "test" not in root_check.stdout:
                print("⚠️  دسترسی root ندارید. رد شدن مانیتورینگ DNS...")
                return
        except:
            return
        
        while self.running:
            try:
                # استفاده از tcpdump برای مانیتورینگ DNS
                cmd = "timeout 5 tcpdump -i any port 53 -c 10 2>/dev/null || echo 'خطا'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.stdout and "خطا" not in result.stdout:
                    dns_requests = []
                    for line in result.stdout.split('\n'):
                        if 'A?' in line:
                            dns_requests.append(line.strip()[:100])
                    
                    if dns_requests:
                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "type": "DNS_REQUESTS",
                            "count": len(dns_requests),
                            "requests": dns_requests[:3]
                        }
                        self.events.append(event)
                        self.log_event(event)
                
                time.sleep(15)  # هر 15 ثانیه
                
            except Exception as e:
                print(f"خطا در مانیتورینگ DNS: {e}")
                time.sleep(5)
    
    def monitor_processes(self):
        """مانیتورینگ فرآیندهای جدید"""
        print("⚙️  مانیتورینگ فرآیندهای سیستم...")
        
        known_processes = set()
        
        while self.running:
            try:
                # دریافت لیست فرآیندها
                cmd = "ps -A -o pid,comm 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                current_processes = set()
                new_processes = []
                
                for line in result.stdout.split('\n')[1:]:  # رد کردن هدر
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            pid, comm = parts[0], parts[1]
                            current_processes.add((pid, comm))
                            
                            if (pid, comm) not in known_processes:
                                new_processes.append(f"{comm} (PID: {pid})")
                
                # ثبت فرآیندهای جدید
                if new_processes:
                    event = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "NEW_PROCESSES",
                        "count": len(new_processes),
                        "processes": new_processes[:5]
                    }
                    self.events.append(event)
                    self.log_event(event)
                
                known_processes = current_processes
                time.sleep(20)  # هر 20 ثانیه
                
            except Exception as e:
                print(f"خطا در مانیتورینگ فرآیندها: {e}")
                time.sleep(5)
    
    def log_event(self, event):
        """ثبت رویداد در فایل لاگ"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except:
            pass
    
    def start_monitoring(self):
        """شروع مانیتورینگ"""
        print("=" * 60)
        print(f"شروع مانیتورینگ بلادرنگ ({self.monitoring_duration} ثانیه)")
        print("=" * 60)
        print("برای توقف Ctrl+C را فشار دهید...\n")
        
        # شروع threadهای مانیتورینگ
        threads = []
        
        network_thread = threading.Thread(target=self.monitor_network_connections)
        network_thread.daemon = True
        threads.append(network_thread)
        
        dns_thread = threading.Thread(target=self.monitor_dns_requests)
        dns_thread.daemon = True
        threads.append(dns_thread)
        
        process_thread = threading.Thread(target=self.monitor_processes)
        process_thread.daemon = True
        threads.append(process_thread)
        
        # شروع همه threadها
        for thread in threads:
            thread.start()
        
        # انتظار برای پایان زمان مانیتورینگ
        try:
            for remaining in range(self.monitoring_duration, 0, -1):
                if not self.running:
                    break
                    
                if remaining % 30 == 0:  # هر 30 ثانیه گزارش
                    print(f"⏳ باقی‌مانده: {remaining//60}:{remaining%60:02d} دقیقه | رویدادها: {len(self.events)}")
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n✋ دریافت سیگنال توقف...")
        
        finally:
            self.running = False
            
            # انتظار برای پایان threadها
            for thread in threads:
                thread.join(timeout=2)
            
            # ذخیره نتایج
            self.save_results()
    
    def save_results(self):
        """ذخیره نتایج مانیتورینگ"""
        print("\n💾 ذخیره نتایج...")
        
        summary = {
            "monitoring_start": datetime.now().isoformat(),
            "duration_seconds": self.monitoring_duration,
            "total_events": len(self.events),
            "events_by_type": {},
            "log_file": self.log_file
        }
        
        # گروه‌بندی رویدادها بر اساس نوع
        for event in self.events:
            event_type = event.get("type", "UNKNOWN")
            if event_type not in summary["events_by_type"]:
                summary["events_by_type"][event_type] = 0
            summary["events_by_type"][event_type] += 1
        
        # ذخیره خلاصه
        summary_file = f"monitoring_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"✅ مانیتورینگ کامل شد!")
        print(f"📊 رویدادهای ثبت شده: {len(self.events)}")
        print(f"📝 لاگ کامل: {self.log_file}")
        print(f"📄 خلاصه گزارش: {summary_file}")
        
        # نمایش خلاصه
        print("\n📋 خلاصه آماری:")
        for event_type, count in summary["events_by_type"].items():
            print(f"   {event_type}: {count} رویداد")

# اجرای اصلی
if __name__ == "__main__":
    print("⚠️  مانیتورینگ بلادرنگ فعالیت‌های سیستم")
    print("این ابزار برای ثبت فعالیت‌های مشکوک طراحی شده است.")
    
    try:
        duration = int(input("مدت زمان مانیتورینگ (ثانیه، پیش‌فرض 300): ") or "300")
        
        if duration > 3600:
            confirm = input(f"⏰ مدت زمان {duration//60} دقیقه است. مطمئن هستید؟ (y/N): ")
            if confirm.lower() != 'y':
                duration = 300
        
        monitor = RealTimeMonitor(duration)
        monitor.start_monitoring()
        
    except ValueError:
        print("❌ زمان وارد شده معتبر نیست.")
    except KeyboardInterrupt:
        print("\n❌ عملیات توسط کاربر لغو شد.")
