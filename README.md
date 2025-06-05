<div align="center">
  <img src="https://img.shields.io/github/languages/count/mss-kubracan/aircrack-ng-?style=flat-square&color=blueviolet" alt="Language Count">
  <img src="https://img.shields.io/github/languages/top/mss-kubracan/aircrack-ng-?style=flat-square&color=1e90ff" alt="Top Language">
  <img src="https://img.shields.io/github/last-commit/mss-kubracan/aircrack-ng-?style=flat-square&color=ff69b4" alt="Last Commit">
  <img src="https://img.shields.io/github/license/mss-kubracan/aircrack-ng-?style=flat-square&color=yellow" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-green?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=flat-square" alt="Contributions">
</div>

# Aircrack-ng WiFiGuard
*Aircrack-ng WiFiGuard*

 WiFiGuard is a sleek, user-friendly tool built on Aircrack-ng to monitor, analyze, and manage WiFi networks by identifying connected devices and selectively disrupting connections for network testing purposes.
 
WiFiGuard, Aircrack-ng üzerine inşa edilmiş, WiFi ağlarını izlemek, analiz etmek ve yönetmek için kullanıcı dostu, şık bir araçtır; bağlı cihazları tespit eder ve ağ testi amacıyla seçilen bağlantıları keser.
---

## Features / *Özellikler*

- Monitor Mode Activation: Seamlessly switches the wireless interface to monitor mode for passive network scanning.  
 Monitör Moduna Geçiş: Kablosuz arayüzü, pasif ağ taraması için sorunsuz bir şekilde monitör moduna geçirir.
- Network Discovery: Uses airodump-ng to detect and list all available WiFi networks in the vicinity.
 Ağ Keşfi: Airodump-ng kullanarak çevrede bulunan tüm WiFi ağlarını tespit eder ve listeler.
- Network Selection: Allows the user to choose a specific WiFi network by displaying available networks.
 Ağ Seçimi: Kullanıcıya mevcut ağları göstererek belirli bir WiFi ağını seçme imkanı sunar.
- Targeted Scanning: Restricts airodump-ng to the selected network’s BSSID and channel for focused analysis.
 Hedefli Tarama: Airodump-ng’yi seçilen ağın BSSID ve kanalına kısıtlayarak odaklanmış analiz yapar.
- Device Listing: Displays all devices connected to the selected WiFi network.
 Cihaz Listeleme: Seçilen WiFi ağına bağlı tüm cihazları listeler.
- Device Selection & Deauthentication: Enables the user to select a specific device and send deauthentication packets to disconnect     it from the router.
 Cihaz Seçimi ve Bağlantı Kesme: Kullanıcının belirli bir cihazı seçmesine ve router ile bağlantısını kesmek için deauthentication    paketleri göndermesine olanak tanır.
-User-Friendly Interface: Simplifies the process with clear prompts for network and device selection, making it accessible for ethical network testing.
Kullanıcı Dostu Arayüz: Ağ ve cihaz seçimi için net yönlendirmelerle süreci basitleştirir, etik ağ testi için erişilebilir hale getirir.

---

## Team / *Ekip*

- 2320191092 - Kübra Can :Technical Developer and Script Writer
  *Kübra Can: Teknik Geliştirici ve Komut Dosyası Yazarı
- 2320191096 - Ayşe Çamır:  Interface Designer and User Experience Manager
  *Ayşe Çamır: Arayüz Tasarımcısı ve Kullanıcı Deneyimi Sorumlusu
- Add more members as needed.  
  *Gerektiğinde daha fazla üye ekleyin.*

---

## Roadmap / *Yol Haritası*

See our plans in [ROADMAP.md](ROADMAP.md).  
*Yolculuğu görmek için [ROADMAP.md](ROADMAP.md) dosyasına göz atın.*

---

## Research / *Araştırmalar*

| Topic / *Başlık*        | Link                                    | Description / *Açıklama*                        |
|-------------------------|-----------------------------------------|------------------------------------------------|
| Aircrack Deep Dive      | [researchs/aircrack.md](researchs/aircrack.md) | In-depth analysis of Aircrack-ng suite. / *Aircrack-ng paketinin derinlemesine analizi.* |
| Example Research Topic  | [researchs/your-research-file.md](researchs/your-research-file.md) | Brief overview of this research. / *Bu araştırmanın kısa bir özeti.* |
| Add More Research       | *Link to your other research files*     | *Description of the research*                  |

---

## Installation / *Kurulum*

1. **Clone the Repository / *Depoyu Klonlayın***:  
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
   cd YOUR_REPO
   ```

2. **Set Up Virtual Environment / *Sanal Ortam Kurulumu*** (Recommended):  
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies / *Bağımlılıkları Yükleyin***:  
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage / *Kullanım*

Run the project:  
*Projeyi çalıştırın:*

```bash
python main.py --input your_file.pcap --output results.txt
```

**Steps**:  
1. Prepare input data (*explain data needed*).  
2. Run the script with arguments (*explain key arguments*).  
3. Check output (*explain where to find results*).  

*Adımlar*:  
1. Giriş verilerini hazırlayın (*ne tür verilere ihtiyaç duyulduğunu açıklayın*).  
2. Betiği argümanlarla çalıştırın (*önemli argümanları açıklayın*).  
3. Çıktıyı kontrol edin (*sonuçları nerede bulacağınızı açıklayın*).

---

## Contributing / *Katkıda Bulunma*

We welcome contributions! To help:  
1. Fork the repository.  
2. Clone your fork (`git clone git@github.com:YOUR_USERNAME/YOUR_REPO.git`).  
3. Create a branch (`git checkout -b feature/your-feature`).  
4. Commit changes with clear messages.  
5. Push to your fork (`git push origin feature/your-feature`).  
6. Open a Pull Request.  

Follow our coding standards (see [CONTRIBUTING.md](CONTRIBUTING.md)).  

*Topluluk katkilerini memnuniyetle karşılıyoruz! Katkıda bulunmak için yukarıdaki adımları izleyin ve kodlama standartlarımıza uyun.*

---

## License / *Lisans*

Licensed under the [MIT License](LICENSE.md).  
*MIT Lisansı altında lisanslanmıştır.*

---

## Acknowledgements / *Teşekkürler* (Optional)

Thanks to:  
- Kübra Can (kubra.can@istinye.edu.tr) Ayşe Çamır (ayse.camir@istinye.edu.tr
- Istinye Universty


*Teşekkürler: Harika kütüphaneler ve ilham kaynakları için.*

---

## Contact / *İletişim* (Optional)

Project Maintainer: [Kübra Can] [Ayşe Çamır] - [kubra.can@istinye.edu.tr] [ayse.camir@istinye.edu.tr]    
Found a bug? Open an issue.  

*Proje Sorumlusu: [Kübra Can /Istinye Universty] - [kubra.can@istinye.edu.tr] [Ayşe Çamır /Istinye Universty] - [ayse.camir@istinye.edu.tr].

Hata bulursanız bir sorun bildirin.*

---

*Replace placeholders (e.g., YOUR_USERNAME/YOUR_REPO) with your project details.*
