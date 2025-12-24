# encoding: utf-8
from burp import IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab
from javax.swing import (JPanel, JButton, JFileChooser, JTextPane, JScrollPane, JOptionPane,
                         JCheckBox, JLabel, JTextField, JTabbedPane, BorderFactory, JSpinner,
                         SpinnerNumberModel, UIManager, JTextArea)
from java.awt import BorderLayout, Dimension, Font, GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter, File
from java.nio.charset import Charset
from java.util import Timer, TimerTask
import datetime, os


class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("SAVER_LOGGER")

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)
        self._callbacks.registerExtensionStateListener(self)

        # Core data storage
        self.log_data = []
        self.request_counter = 0
        self.runtime_id = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        
        # Request tracking for insertion points and timing
        self.request_tracking = {}  # Maps request_id -> {start_time, end_time, insertion_points}

        # Settings
        self.auto_backup_enabled = True
        self.backup_folder = os.path.join(os.path.expanduser("~"), "Desktop")
        self.backup_interval_seconds = 60
        self.backup_timer = None

        self._init_ui()
        self._callbacks.addSuiteTab(self)
        self._start_backup_scheduler()

    # ------------- UI ------------- #

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())
        self.tabs = JTabbedPane()

        self._build_dashboard_tab()
        self._build_settings_tab()

        self.panel.add(self.tabs, BorderLayout.CENTER)

    def _build_dashboard_tab(self):
        dash = JPanel(BorderLayout())
        dash.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        header = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("SAVER_LOGGER - Store All Logs")
        title.setFont(Font("Arial", Font.BOLD, 24))
        header.add(title)
        dash.add(header, BorderLayout.NORTH)

        btn_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))

        export_btn = JButton("Export CSV")
        export_btn.setPreferredSize(Dimension(140, 35))
        export_btn.addActionListener(self.export_csv_manual)
        btn_panel.add(export_btn)

        backup_btn = JButton("Backup Now")
        backup_btn.setPreferredSize(Dimension(140, 35))
        backup_btn.addActionListener(self.backup_now)
        btn_panel.add(backup_btn)

        clear_btn = JButton("Clear Logs")
        clear_btn.setPreferredSize(Dimension(140, 35))
        clear_btn.addActionListener(self.clear_logs)
        btn_panel.add(clear_btn)

        dash.add(btn_panel, BorderLayout.CENTER)

        info = JTextPane()
        info.setContentType("text/html")
        info.setEditable(False)
        info.setBackground(UIManager.getColor("Panel.background"))
        info.setText("""
        <html><body style='font-family: Arial; font-size: 12px;'>
        <h3 style='color:#ff6600;font-size: 18px;'>Extension Info</h3>
        <ul>
        <li>Logs HTTP requests from all Burp tools</li>
        <li>Tracks insertion points, request counts, and timing</li>
        <li>Auto-saves log file on crash / closures</li>
        <li>Manual export & backup supported</li>
        <li>Interval-based auto-backups to custom path</li>
        </ul>
        <p><b>Author:</b> Sachhit Anasane</p>
        <p><b>Session ID:</b> %s</p>
        </body></html>
        """ % self.runtime_id)

        dash.add(JScrollPane(info), BorderLayout.SOUTH)

        self.tabs.addTab("Dashboard", dash)

    def _build_settings_tab(self):
        settings = JPanel(BorderLayout())
        settings.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        config = JPanel(GridBagLayout())
        config.setBorder(BorderFactory.createTitledBorder("Backup Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = gbc.WEST

        self.enable_backup = JCheckBox("Enable Automatic Backup", True)

        self.interval_spinner = JSpinner(SpinnerNumberModel(60, 10, 3600, 10))
        self.interval_spinner.setPreferredSize(Dimension(90, 25))

        self.folder_input = JTextField(os.path.join(os.path.expanduser("~"), "Desktop"), 30)
        browse = JButton("Browse")
        browse.addActionListener(self.select_folder)

        save = JButton("Save Settings")
        save.addActionListener(self.save_settings)

        # UI placement
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2
        config.add(self.enable_backup, gbc)

        gbc.gridy = 1; gbc.gridwidth = 1
        config.add(JLabel("Backup Interval (seconds):"), gbc)
        gbc.gridx = 1
        config.add(self.interval_spinner, gbc)

        gbc.gridx = 0; gbc.gridy = 2
        config.add(JLabel("Backup Folder:"), gbc)
        gbc.gridx = 1
        config.add(self.folder_input, gbc)
        gbc.gridx = 2
        config.add(browse, gbc)

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3
        config.add(save, gbc)

        settings.add(config, BorderLayout.NORTH)

        self.status_area = JTextArea(12, 50)
        self.status_area.setEditable(False)
        self.status_area.append("Extension Loaded\n")
        self.status_area.append("Auto-backup ready\n")
        self.status_area.append("HTTP logging active\n")
        self.status_area.append("Backup location: " + self.backup_folder + "\n")
        settings.add(JScrollPane(self.status_area), BorderLayout.CENTER)

        self.tabs.addTab("Settings", settings)

    # ------------- SETTINGS ACTIONS ------------- #

    def select_folder(self, event):
        ch = JFileChooser()
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        ch.setCurrentDirectory(File(self.backup_folder))
        if ch.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            self.folder_input.setText(ch.getSelectedFile().getAbsolutePath())

    def save_settings(self, event):
        self.auto_backup_enabled = self.enable_backup.isSelected()
        self.backup_folder = self.folder_input.getText()
        self.backup_interval_seconds = int(self.interval_spinner.getValue())
        
        self._start_backup_scheduler()
        
        self.status_area.append("\n[%s] Settings saved!" % datetime.datetime.now().strftime('%H:%M:%S'))
        self.status_area.append("\n  - Auto-backup: %s" % ("Enabled" if self.auto_backup_enabled else "Disabled"))
        self.status_area.append("\n  - Interval: %d seconds" % self.backup_interval_seconds)
        self.status_area.append("\n  - Location: %s\n" % self.backup_folder)
        
        JOptionPane.showMessageDialog(self.panel, "Settings saved successfully!")

    # ------------- BACKUP SCHEDULER ------------- #

    def _start_backup_scheduler(self):
        if self.backup_timer:
            self.backup_timer.cancel()

        if not self.auto_backup_enabled:
            self.status_area.append("\n[%s] Auto-backup disabled" % datetime.datetime.now().strftime('%H:%M:%S'))
            return

        self.backup_timer = Timer("SAVER_LOGGER_AutoSave", True)

        class Task(TimerTask):
            def run(task_self):
                if self.auto_backup_enabled:
                    self._auto_backup()

        delay = 10000  # 10 seconds initial delay
        period = self.backup_interval_seconds * 1000
        self.backup_timer.schedule(Task(), delay, period)
        
        self.status_area.append("\n[%s] Auto-backup scheduler started (every %ds)" % 
                                (datetime.datetime.now().strftime('%H:%M:%S'), self.backup_interval_seconds))

    # ------------- HTTP LOGGING ------------- #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Captures HTTP requests and responses with full metadata including:
        - Insertion points (for Intruder/Scanner)
        - Request timing (start/end)
        - Request count per URL
        """
        if messageIsRequest:
            # Start tracking this request
            req = self._helpers.analyzeRequest(messageInfo)
            url = str(req.getUrl())
            request_bytes = messageInfo.getRequest()
            tool = self._callbacks.getToolName(toolFlag)
            
            # Count insertion points based on tool and markers
            insertion_point_count = 0
            
            try:
                # Convert request bytes to string for marker detection
                request_str = self._helpers.bytesToString(request_bytes)
                
                # For Intruder: Count § markers (payload positions)
                if tool == "Intruder":
                    insertion_point_count = request_str.count('§') / 2  # Each insertion point has 2 markers
                
                # For Scanner: Estimate based on parameters
                elif tool == "Scanner":
                    # Count parameters (query + body) as potential insertion points
                    params = req.getParameters()
                    if params:
                        insertion_point_count = len(params)
                
                # For other tools with parameters
                else:
                    # Count only if there are actual parameters
                    params = req.getParameters()
                    if params and len(params) > 0:
                        insertion_point_count = len(params)
                        
            except Exception as e:
                insertion_point_count = 0
            
            # Track request start time
            start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Create tracking entry
            req_id = self.request_counter + 1
            self.request_tracking[req_id] = {
                'start_time': start_time,
                'end_time': None,
                'insertion_points': int(insertion_point_count),
                'url': url
            }
            
        else:
            # Response received - finalize the log entry
            req = self._helpers.analyzeRequest(messageInfo)
            res_bytes = messageInfo.getResponse()

            status = "-"
            if res_bytes:
                try:
                    res = self._helpers.analyzeResponse(res_bytes)
                    status = str(res.getStatusCode())
                except:
                    status = "Error"

            url = str(req.getUrl())
            host = messageInfo.getHttpService().getHost()
            method = req.getMethod()
            tool = self._callbacks.getToolName(toolFlag)
            end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            self.request_counter += 1
            
            # Get tracking data for this request
            tracking = self.request_tracking.get(self.request_counter, {})
            start_time = tracking.get('start_time', end_time)
            insertion_points = tracking.get('insertion_points', 0)
            
            # Count how many times this URL has been requested
            request_count = sum(1 for entry in self.log_data if entry[3] == url) + 1
            
            # Store complete log entry with all required columns
            self.log_data.append([
                self.request_counter,      # Serial No
                host,                       # Host
                method,                     # Request Method
                url,                        # URL
                status,                     # Status Code
                tool,                       # Tool Name
                request_count,              # Request Count
                insertion_points,           # Insertion Point Count
                start_time,                 # Start Time
                end_time                    # End Time
            ])
            
            # Clean up old tracking data to prevent memory bloat
            if self.request_counter in self.request_tracking:
                del self.request_tracking[self.request_counter]

    def newScanIssue(self, issue):
        """Scanner listener implementation"""
        pass

    # ------------- EXPORT + BACKUP ------------- #

    def backup_now(self, event):
        """Manual backup button - saves to configured backup folder with timestamp"""
        timestamp = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
        filename = "SAVER_LOGGER_BACKUP_%s.csv" % timestamp
        filepath = os.path.join(self.backup_folder, filename)
        
        result = self._write_full_csv(filepath)
        if result:
            self.status_area.append("\n[%s] Manual backup completed: %d requests" % 
                                    (datetime.datetime.now().strftime('%H:%M:%S'), len(self.log_data)))
            JOptionPane.showMessageDialog(self.panel, 
                                          "Backup completed successfully!\n%d requests saved to:\n%s" % 
                                          (len(self.log_data), filepath))
        else:
            JOptionPane.showMessageDialog(self.panel, "Backup failed! Check console for errors.")

    def _auto_backup(self):
        """Automatic backup triggered by timer - overwrites same file"""
        if not self.log_data:
            return
        
        # Auto-backup uses a consistent filename (overwrites each time)
        filename = "SAVER_LOGGER_AUTOSAVE.csv"
        filepath = os.path.join(self.backup_folder, filename)
        
        result = self._write_full_csv(filepath)
        if result:
            self.status_area.append("\n[%s] Auto-backup: %d requests saved" % 
                                    (datetime.datetime.now().strftime('%H:%M:%S'), len(self.log_data)))

    def export_csv_manual(self, event):
        """Manual CSV export with file chooser"""
        if not self.log_data:
            JOptionPane.showMessageDialog(self.panel, "No data to export!")
            return

        ch = JFileChooser()
        ch.setSelectedFile(File("SAVER_LOGGER_Export_%s.csv" % 
                                datetime.datetime.now().strftime('%Y%m%d_%H%M%S')))
        
        if ch.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            filepath = ch.getSelectedFile().getAbsolutePath()
            if not filepath.endswith('.csv'):
                filepath += '.csv'
            
            result = self._write_full_csv(filepath)
            if result:
                JOptionPane.showMessageDialog(self.panel, 
                                              "Export successful!\n%d requests saved to:\n%s" % 
                                              (len(self.log_data), filepath))
            else:
                JOptionPane.showMessageDialog(self.panel, "Export failed! Check console for errors.")

    def _write_full_csv(self, filepath):
        """
        Write ALL log data to a single CSV file with complete column structure.
        
        Columns:
        Serial No, Host, Request Method, URL, Status Code, Tool Name, 
        Request Count, Insertion Point Count, Start Time, End Time
        """
        if not self.log_data:
            return False

        try:
            # Always overwrite with complete data (not append)
            fos = FileOutputStream(filepath, False)  # False = overwrite
            writer = BufferedWriter(OutputStreamWriter(fos, Charset.forName("UTF-8")))

            # Header metadata
            writer.write("# Generated By: SAVER_LOGGER\n")
            writer.write("# Session ID: %s\n" % self.runtime_id)
            writer.write("# Export Time: %s\n" % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            writer.write("# Total Requests: %d\n\n" % len(self.log_data))
            
            # Column headers - EXACTLY as specified
            writer.write("Serial No,Host,Request Method,URL,Status Code,Tool Name,Request Count,Insertion Point Count,Start Time,End Time\n")

            # Write ALL data rows
            for row in self.log_data:
                # Sanitize data: replace commas, newlines, and carriage returns
                safe = [str(col).replace(",", ";").replace("\n", " ").replace("\r", " ") for col in row]
                writer.write(",".join(safe) + "\n")

            # Footer metadata for authenticity
            writer.write("\n# --- FOOTER METADATA ---\n")
            writer.write("# Burp Suite Version: %s\n" % self._callbacks.getBurpVersion()[0])
            writer.write("# Exported: %s\n" % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            writer.write("# Runtime ID: %s\n" % self.runtime_id)
            writer.write("# Total Requests Logged: %d\n" % len(self.log_data))

            writer.flush()
            writer.close()
            return True

        except Exception as e:
            print("[SAVER_LOGGER] Export failed: %s" % str(e))
            import traceback
            traceback.print_exc()
            return False

    def clear_logs(self, event):
        """Clear all logged data with confirmation"""
        confirm = JOptionPane.showConfirmDialog(
            self.panel,
            "Are you sure you want to clear all %d logged requests?" % len(self.log_data),
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if confirm == JOptionPane.YES_OPTION:
            cleared_count = len(self.log_data)
            self.log_data = []
            self.request_counter = 0
            self.request_tracking = {}
            
            self.status_area.append("\n[%s] All logs cleared (%d requests removed)" % 
                                    (datetime.datetime.now().strftime('%H:%M:%S'), cleared_count))
            JOptionPane.showMessageDialog(self.panel, "Logs cleared successfully!")

    # ------------- TAB INTERFACE ------------- #

    def getTabCaption(self):
        return "SAVER_LOGGER"

    def getUiComponent(self):
        return self.panel

    # ------------- CLEANUP & EXIT HANDLER ------------- #

    def extensionUnloaded(self):
        """
        Called when extension is unloaded or Burp closes/crashes.
        Performs final backup with timestamped filename.
        """
        if self.backup_timer:
            self.backup_timer.cancel()
        
        # Final backup on exit with timestamp
        if self.log_data:
            timestamp = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
            filename = "SAVER_LOGGER_AUTOSAVE_%s.csv" % timestamp
            filepath = os.path.join(self.backup_folder, filename)
            
            self._write_full_csv(filepath)
            print("[SAVER_LOGGER] Exit backup completed: %d requests saved to %s" % 
                  (len(self.log_data), filepath))
        else:
            print("[SAVER_LOGGER] Extension unloaded (no data to save)")
