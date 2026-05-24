# SNMP-Network-Topology

# 🌐 SNMP 網路拓樸智能管理平台 (SNMP Network Topology Manager)

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![Vis.js](https://img.shields.io/badge/Vis.js-Network-orange.svg)](https://visjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

本專案是一個基於 **Python + Flask** 與 **Vis.js** 開發的輕量級、高效能網路拓樸管理系統。透過非同步 SNMP 探測技術，系統能自動掃描網段、解析 LLDP 鄰居關係，並動態繪製出具備實體連線狀態的互動式網路拓樸圖。專為企業 IT 網管與資安 ISO 27001 稽核報表所設計。

---

## ✨ 核心功能 (Key Features)

### 1. 🚀 智慧化 SNMP 網段探索
* **非同步高併發掃描：** 支援設定 `/24` 網段與多組 SNMP Community 字串，快速找出網域內的交換器、防火牆與路由器。
* **自動設備識別：** 自動解析 `sysDescr`，精準辨識設備廠牌（如 Aruba, Ruckus, MikroTik, Cisco, Fortinet 等）與硬體型號。
* **LLDP 交叉拼湊演算法：** 即便設備漏發 `sysName`，系統也能透過 `PortID`、`PortDesc` 與 `MgmtIP` 交叉比對，精準畫出實體對接線路。

### 2. 🎨 專業級互動式拓樸圖 (Vis.js)
* **動態資料流與狀態監控：** 視覺化顯示 10G（藍色）、1G（綠色）、100M（橘色）實體線路與動態資料流光點。即時標示設備斷線 (🔴) 或 SNMP 異常 (⚠️)。
* **職人級排版控制：** * 支援滑鼠拖曳、滾輪縮放。
  * 支援 `Ctrl` 多選設備。
  * 支援鍵盤方向鍵精準微調（X 軸 10px 網格磁吸，按住 `Shift` 50px；Y 軸嚴格依照設備層級跳躍）。
  * 內建「強制對齊」按鈕，一鍵讓同層級設備水平歸位。
* **版面記憶插槽：** 提供 4 組記憶插槽 (Slot 0~3)，可永久保存您精心調整好的拓樸版面。

### 3. 💾 極致的圖表匯出引擎 (Export Engine)
內建純前端渲染的高解析度匯出工具，完美解決 Canvas 匯出模糊與截斷的問題：
* **4K 高畫質圖片：** 瞬間於背景將畫布放大至 4K (3840x2160) 解析度並匯出 PNG。
* **無限放大向量圖 (SVG)：** 動態測量真實字體寬高，匯出完美排版、無重疊的向量 `.svg`。
* **離線互動版 (HTML)：** 將當前所有資料與物理引擎一鍵封裝成**單一獨立的 HTML 檔案**。不需依賴後端，即可透過瀏覽器離線查看、拖曳與點擊檢視設備資訊！
* **PDF 稽核報表：** 一鍵產出包含「4K 拓樸圖」、「資產明細清單」與「實體線路對接紀錄」的 A4 橫式維運報告。

### 4. 🗄️ 設備清單管理與 Excel 整合
* 內建「設備管理」分頁，可直接在網頁表格上新增、修改設備的 IP、層級 (Level)、放置區域等屬性。
* 支援匯出/匯入 `.csv` (Excel 友善) 與 `.json` 格式，方便大量批次建檔。

---

## 📊 系統可擷取與顯示之資料

本系統深度挖掘並結構化顯示以下網路資訊：

* **基礎資產資訊：** IP 位址、主機名稱 (`sysName`)、設備廠牌、硬體型號、放置區域 (`sysLocation`)、管理層級 (L1~L6)。
* **實體線路對接資訊：** * 本機端 Port 名稱 ⟷ 遠端設備名稱與 Port 名稱。
  * 介面協定速率 (`ifSpeed` / `ifHighSpeed`)。
* **右鍵進階 SNMP 原始資料庫 (Raw MIBs)：** 對著拓樸圖上的設備點擊 **「滑鼠右鍵」**，即可開啟雙分頁浮動視窗，檢視：
  1. 完整系統描述摘要 (`sysDescr`)。
  2. JSON 格式的底層 MIB 原始數據（包含 `LLDP_SysNames`, `LLDP_PortDesc`, `ifName`, `ifPhysAddress` 等 8 大關鍵 OID 樹狀結構）。

---

## 🛠️ 技術堆疊與語言 (Tech Stack)

* **後端 (Backend)：** Python 3.8+ 
  * 網頁框架：`Flask`
  * SNMP 引擎：`PySNMP` (基於 `asyncio` 非同步架構)
  * 資料庫：`SQLite3` (內建，輕量無須額外安裝)
* **前端 (Frontend)：** HTML5, CSS3, JavaScript (Vanilla)
  * UI 框架：`Bootstrap 5` (含 Bootstrap Icons)
  * 繪圖引擎：`Vis.js Network`

---

## 💻 支援作業系統 (Supported OS)

本系統為標準 Web 應用程式，具備完全的跨平台相容性：
* **Windows** (Windows 10 / 11 / Server)
* **Linux** (Ubuntu / Debian / CentOS / RHEL)
* **macOS** *(註：後端 Ping 探測機制已自動相容 Windows 的 `-n` 與 Linux/macOS 的 `-c` 參數)*

---

## 🚀 安裝與執行 (Installation & Usage)

1. **環境準備：** 確保已安裝 Python 3.8 或以上版本。
2. **複製專案：**
   ```bash
   git clone [https://github.com/yourusername/snmp-topology-manager.git](https://github.com/yourusername/snmp-topology-manager.git)
   cd snmp-topology-manager

```

3. **安裝依賴套件：**
```bash
pip install flask pysnmp

```


4. **啟動伺服器：**
```bash
python app.py

```


5. **開啟系統：** 打開瀏覽器並前往 `http://127.0.0.1:5000`。
6. **開始使用：** 點擊右上角進入「設備管理」進行「網段探索」，加入設備後返回首頁點擊「重新掃描」即可生成拓樸圖！

---

## 📄 授權條款 (License)

本專案採用 **[MIT License](https://www.google.com/search?q=LICENSE)** 授權。您可以自由使用、修改、散佈本程式碼，不論是商業或非商業用途，唯須保留原作者版權聲明。

```

```
