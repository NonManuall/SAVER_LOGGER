# 🔐 SAVER_LOGGER - Burp Suite Extension

**Author:** Sachhit Anasane  
**Version:** 1.0  
**Date:** December 2025  

---

## 🧭 Overview

SAVER_LOGGER is a professionally engineered extension for Burp Suite that automatically logs all HTTP requests across tools like Proxy, Scanner, Repeater, Intruder, Collaborator, and Dashboard. It captures comprehensive request metadata including insertion points, request timing, status codes, and tool sources—then exports structured CSV logs with complete audit trails.

---

## ✨ Key Features

### Core Functionality
- ✅ **Comprehensive Logging**: Captures every HTTP request from all Burp tools
- ✅ **Complete Metadata**: Host, method, URL, status code, tool source, insertion points, and timing
- ✅ **Insertion Point Detection**: 
  - Intruder: Counts `§` payload markers
  - Scanner: Counts tested parameters
  - Other tools: Identifies available parameters
- ✅ **Request Counting**: Tracks how many times each URL has been accessed
- ✅ **Timing Analysis**: Records start and end timestamps for each request

### Export & Backup
- ✅ **Auto-backup on Exit**: Crash-safe backup with timestamped filename (`SAVER_LOGGER_AUTOSAVE_DDMMYYYY_HHMMSS.csv`)
- ✅ **Periodic Auto-backup**: Configurable interval (10-3600 seconds) to custom folder
- ✅ **Manual Export**: User-triggered CSV export with file chooser dialog
- ✅ **Manual Backup**: Instant timestamped backup (`SAVER_LOGGER_BACKUP_DDMMYYYY_HHMMSS.csv`)
- ✅ **Single File Approach**: Periodic backups overwrite same file to prevent fragmentation

### Data Integrity
- ✅ **UTF-8 Encoding**: Full international character support
- ✅ **CSV Sanitization**: Automatic handling of commas, newlines, and special characters
- ✅ **Footer Metadata**: Burp version, export timestamp, and unique runtime ID
- ✅ **Session Tracking**: Unique session identifier for audit trails

### User Interface
- ✅ **Dashboard Tab**: Quick access to export, backup, and clear functions
- ✅ **Settings Tab**: Configure backup folder, interval, and enable/disable auto-backup
- ✅ **Status Area**: Real-time logging of all operations with timestamps
- ✅ **Confirmation Dialogs**: User-friendly feedback for all actions

---

## 📦 Installation

### Step 1: Install Jython
1. Download Jython standalone JAR (v2.7.3 or later):
   ```
   https://www.jython.org/download.html
   ```

### Step 2: Configure Burp Suite
1. Open Burp Suite
2. Navigate to: **Extensions > Extension Settings > Python Environment**
3. Set location of Jython standalone JAR file

### Step 3: Load Extension
1. Go to: **Extensions > Installed > Add**
2. **Extension type**: Python
3. **Extension file**: Select `saver_logger.py`
4. Click **Next**
5. Verify "SAVER_LOGGER" appears in the Extensions list

### Step 4: Verify Installation
- A new tab labeled **SAVER_LOGGER** should appear in Burp Suite
- Check the Dashboard for session information
- Review Settings to configure backup preferences

---

## 🛠️ Usage Instructions

### Basic Operation
1. **Automatic Logging**: All HTTP traffic is logged automatically once the extension is loaded
2. **Access Dashboard**: Click the **SAVER_LOGGER** tab to view controls and info
3. **Configure Settings**: Navigate to the **Settings** tab to customize backup behavior

### Dashboard Actions

#### Export CSV
- Opens file chooser dialog
- Allows custom filename and location
- Default name: `SAVER_LOGGER_Export_YYYYMMDD_HHMMSS.csv`
- Exports all logged requests with complete metadata

#### Backup Now
- Creates instant timestamped backup
- Saves to configured backup folder
- Filename: `SAVER_LOGGER_BACKUP_DDMMYYYY_HHMMSS.csv`
- Shows confirmation with file path

#### Clear Logs
- Removes all logged requests from memory
- Requires user confirmation
- Does not delete previously exported files

### Settings Configuration

#### Auto-Backup Settings
- **Enable/Disable**: Toggle automatic periodic backups
- **Backup Interval**: Set time between auto-backups (10-3600 seconds)
- **Backup Folder**: Choose custom directory for backups
- **Default Location**: Desktop

#### How Auto-Backup Works
- **Periodic Backup**: Overwrites `SAVER_LOGGER_AUTOSAVE.csv` at configured interval
- **Exit Backup**: Creates timestamped file on Burp close/crash
- **Single File**: Prevents file proliferation during normal operation

### File Naming Conventions

| Backup Type | Filename Pattern | Example |
|-------------|------------------|---------|
| Periodic Auto-backup | `SAVER_LOGGER_AUTOSAVE.csv` | `SAVER_LOGGER_AUTOSAVE.csv` |
| Exit/Crash Backup | `SAVER_LOGGER_AUTOSAVE_DDMMYYYY_HHMMSS.csv` | `SAVER_LOGGER_AUTOSAVE_24122025_143052.csv` |
| Manual Backup | `SAVER_LOGGER_BACKUP_DDMMYYYY_HHMMSS.csv` | `SAVER_LOGGER_BACKUP_24122025_143052.csv` |
| Manual Export | `SAVER_LOGGER_Export_YYYYMMDD_HHMMSS.csv` | `SAVER_LOGGER_Export_20251224_143052.csv` |

---

## 📄 CSV Export Format

### Column Structure

All exported CSV files contain the following 10 columns:

| Column | Description |
|--------|-------------|
| **Serial No** | Sequential request identifier (1, 2, 3...) |
| **Host** | Target hostname or IP address |
| **Request Method** | HTTP method (GET, POST, PUT, DELETE, etc.) |
| **URL** | Complete request URL including query parameters |
| **Status Code** | HTTP response status code (200, 404, 500, etc.) |
| **Tool Name** | Burp tool that generated the request (Proxy, Scanner, Repeater, Intruder) |
| **Request Count** | Number of times this specific URL has been requested |
| **Insertion Point Count** | Number of insertion points/parameters detected |
| **Start Time** | Request initiation timestamp (YYYY-MM-DD HH:MM:SS) |
| **End Time** | Response received timestamp (YYYY-MM-DD HH:MM:SS) |

### Insertion Point Detection Logic

| Tool | Detection Method |
|------|------------------|
| **Intruder** | Counts `§` payload markers (divided by 2) |
| **Scanner** | Counts all HTTP parameters being tested |
| **Other Tools** | Counts available parameters in request |

### Header Metadata

Every CSV file includes:
```
# Generated By: SAVER_LOGGER
# Session ID: 20251224143052
# Export Time: 2025-12-24 14:30:52
# Total Requests: 1547
```

### Footer Metadata

Every CSV file concludes with:
```
# --- FOOTER METADATA ---
# Burp Suite Version: Burp Suite Professional 2024.x.x
# Exported: 2025-12-24 14:30:52
# Runtime ID: 20251224143052
# Total Requests Logged: 1547
```

### Sample CSV Output

```csv
# Generated By: SAVER_LOGGER
# Session ID: 20251224143052
# Export Time: 2025-12-24 14:30:52
# Total Requests: 3

Serial No,Host,Request Method,URL,Status Code,Tool Name,Request Count,Insertion Point Count,Start Time,End Time
1,example.com,GET,https://example.com/api/users,200,Proxy,1,0,2025-12-24 14:25:10,2025-12-24 14:25:11
2,example.com,POST,https://example.com/api/login,200,Repeater,1,2,2025-12-24 14:26:15,2025-12-24 14:26:16
3,example.com,GET,https://example.com/api/data?id=§1§&type=§test§,200,Intruder,1,2,2025-12-24 14:28:20,2025-12-24 14:28:21

# --- FOOTER METADATA ---
# Burp Suite Version: Burp Suite Professional 2024.9.2
# Exported: 2025-12-24 14:30:52
# Runtime ID: 20251224143052
# Total Requests Logged: 3
```

---

## 🔧 Technical Details

### Architecture
- **Language**: Jython (Python for Java)
- **Burp API**: IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab
- **Encoding**: UTF-8 for international character support
- **Threading**: Timer-based background scheduler for auto-backups

### Memory Management
- Automatic cleanup of request tracking data after processing
- Efficient storage of only essential metadata
- No memory leaks during long-running sessions

### Crash Safety
- `extensionUnloaded()` callback ensures data is saved on:
  - Manual Burp Suite closure
  - Burp Suite crashes
  - Extension unload/reload
  - System shutdowns

### Data Sanitization
- Commas replaced with semicolons in data fields
- Newline and carriage return characters removed
- Special characters properly escaped

---

## 🎯 Use Cases

### Security Testing
- Track all requests during penetration testing
- Maintain audit trail of testing activities
- Document insertion points for vulnerability research
- Analyze request patterns and timing

### Compliance & Reporting
- Generate comprehensive test reports
- Export data for compliance documentation
- Create audit logs for security assessments
- Track tool usage and coverage

### Performance Analysis
- Measure request/response timing
- Identify slow endpoints
- Analyze request frequency per URL
- Monitor testing efficiency

### Collaboration
- Share structured test data with team members
- Import into analysis tools (Excel, Python, R)
- Create reproducible testing workflows
- Document findings with complete context

---

## 📈 Best Practices

1. **Regular Exports**: Periodically export data during long testing sessions
2. **Backup Configuration**: Set auto-backup to 300-600 seconds for balanced performance
3. **Disk Space**: Monitor available space when logging heavy traffic
4. **Clear Logs**: Clear logs after exporting to manage memory usage
5. **Naming Convention**: Use descriptive names when manually exporting for specific tests

---

## 🔒 Privacy & Security

- ✅ All data stored locally on your machine
- ✅ No external network connections
- ✅ No telemetry or analytics
- ✅ No data uploaded to external servers
- ✅ Full control over exported files

---

**Happy Testing! 🔐🚀**
