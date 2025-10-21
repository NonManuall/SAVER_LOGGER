# encoding: utf-8
from burp import IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab
from javax.swing import (JPanel, JButton, JFileChooser, JTextPane, JScrollPane, JOptionPane,
                         JCheckBox, JLabel, JTextField, BoxLayout, JSplitPane, JFileChooser,
                         JTabbedPane, BorderFactory, SwingConstants, JTextArea, JTable,
                         JComboBox, JSpinner, SpinnerNumberModel, UIManager)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension, Color, Font, GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter
from java.nio.charset import Charset
from java.util import Timer, TimerTask
import datetime
import os


class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("SAVER_LOGGER")

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)
        self._callbacks.registerExtensionStateListener(self)

        self.log_data = []
        self.request_counter = 0
        self.tracking_map = {}
        self.runtime_id = str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
        self.last_export_count = 0

        self.auto_backup_enabled = True
        self.backup_interval = 60
        self.auto_backup_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.backup_timer = None

        self._init_ui()
        self._callbacks.addSuiteTab(self)
        self._start_backup_scheduler()

    # --------------------- UI ------------------------

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())
        self.tabbed_pane = JTabbedPane()
        self._create_dashboard_tab()
        self._create_settings_tab()
        self.panel.add(self.tabbed_pane, BorderLayout.CENTER)

    def _create_dashboard_tab(self):
        dashboard_panel = JPanel(BorderLayout())
        dashboard_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        title_label = JLabel("SAVER_LOGGER - Store All Logs")
        title_label.setFont(Font("Arial", Font.BOLD, 28))
        header_panel.add(title_label)
        dashboard_panel.add(header_panel, BorderLayout.NORTH)

        actions_panel = self._create_quick_actions_panel()
        dashboard_panel.add(actions_panel, BorderLayout.CENTER)

        self.tabbed_pane.addTab("Dashboard", dashboard_panel)

    def _create_quick_actions_panel(self):
        actions_panel = JPanel(BorderLayout())
        actions_panel.setBorder(BorderFactory.createTitledBorder("Quick Actions"))

        buttons_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))

        export_btn = JButton("Export CSV")
        export_btn.setPreferredSize(Dimension(120, 35))
        export_btn.addActionListener(self.export_csv)
        buttons_panel.add(export_btn)

        clear_btn = JButton("Clear Logs")
        clear_btn.setPreferredSize(Dimension(120, 35))
        clear_btn.addActionListener(self.clear_logs)
        buttons_panel.add(clear_btn)

        backup_btn = JButton("Backup Now")
        backup_btn.setPreferredSize(Dimension(120, 35))
        backup_btn.addActionListener(self.backup_now)
        buttons_panel.add(backup_btn)

        actions_panel.add(buttons_panel, BorderLayout.NORTH)

        info_area = JTextPane()
        info_area.setContentType("text/html")
        info_area.setEditable(False)
        info_area.setBackground(UIManager.getColor("Panel.background"))
        info_area.setForeground(UIManager.getColor("Label.foreground"))

        info_html = """
        <html><body style='font-family: Arial; font-size: 13px; line-height: 1.6;'>
        <h2 style='color: #ff6600;'>SAVER_LOGGER DETAILS</h2>
        <p><strong>Author:</strong> Sachhit Anasane</p>
        <ul>
        <li>Logs every HTTP request from all Burp tools</li>
        <li>Auto-saves log file on crash / closures</li>
        <li>Interval-based auto-backups to custom path</li>
        <li>Manual export to CSV anytime</li>
        </ul>
        </body></html>
        """
        info_area.setText(info_html)
        actions_panel.add(JScrollPane(info_area), BorderLayout.CENTER)
        return actions_panel

    def _create_settings_tab(self):
        settings_panel = JPanel(BorderLayout())
        settings_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        form_panel = JPanel(GridBagLayout())
        form_panel.setBorder(BorderFactory.createTitledBorder("Backup Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST

        gbc.gridx = 0
        gbc.gridy = 0
        self.enable_backup = JCheckBox("Enable Automatic Backup", True)
        self.enable_backup.addActionListener(self.on_backup_toggle)
        form_panel.add(self.enable_backup, gbc)

        gbc.gridx = 0
        gbc.gridy = 1
        form_panel.add(JLabel("Backup Interval (seconds):"), gbc)

        gbc.gridx = 1
        gbc.gridy = 1
        self.interval_spinner = JSpinner(SpinnerNumberModel(60, 10, 3600, 10))
        self.interval_spinner.setPreferredSize(Dimension(100, 25))
        form_panel.add(self.interval_spinner, gbc)

        gbc.gridx = 0
        gbc.gridy = 2
        form_panel.add(JLabel("Backup Folder:"), gbc)

        gbc.gridx = 1
        gbc.gridy = 2
        self.folder_input = JTextField(self.auto_backup_path)
        form_panel.add(self.folder_input, gbc)

        gbc.gridx = 2
        gbc.gridy = 2
        browse_btn = JButton("Browse")
        browse_btn.addActionListener(self.select_folder)
        form_panel.add(browse_btn, gbc)

        gbc.gridx = 0
        gbc.gridy = 3
        gbc.gridwidth = 3
        save_btn = JButton("Save Settings")
        save_btn.addActionListener(self.save_settings)
        form_panel.add(save_btn, gbc)

        settings_panel.add(form_panel, BorderLayout.NORTH)

        self.status_area = JTextArea(10, 50)
        self.status_area.setEditable(False)
        self.status_area.setBackground(UIManager.getColor("Panel.background"))
        self.status_area.setForeground(UIManager.getColor("Label.foreground"))
        self.status_area.setText("Extension loaded successfully.\nAuto-backup scheduler started.\nReady to log HTTP requests.")

        settings_panel.add(JScrollPane(self.status_area), BorderLayout.CENTER)
        self.tabbed_pane.addTab("Autobackup Settings", settings_panel)

    # --------------------- Logic ------------------------

    def on_backup_toggle(self, event):
        self.auto_backup_enabled = self.enable_backup.isSelected()
        if self.auto_backup_enabled:
            self._start_backup_scheduler()
            self.status_area.append("\nAuto-backup enabled.")
        else:
            if self.backup_timer:
                self.backup_timer.cancel()
            self.status_area.append("\nAuto-backup stopped.")

    def _start_backup_scheduler(self):
        if hasattr(self, "backup_timer") and self.backup_timer is not None:
            self.backup_timer.cancel()

        self.backup_timer = Timer("AutoBackupTimer", True)

        class BackupTask(TimerTask):
            def run(task_self):
                if self.auto_backup_enabled:
                    self.export_csv(auto=True, is_backup=True)

        interval_ms = int(self.interval_spinner.getValue()) * 1000
        self.backup_timer.schedule(BackupTask(), interval_ms, interval_ms)

    def select_folder(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Select Auto Backup Folder")
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            self.folder_input.setText(chooser.getSelectedFile().getAbsolutePath())

    def save_settings(self, event):
        try:
            self.auto_backup_enabled = self.enable_backup.isSelected()
            self.backup_interval = int(self.interval_spinner.getValue())
            self.auto_backup_path = self.folder_input.getText().strip()
            self.status_area.append("\nSettings saved successfully.")
            JOptionPane.showMessageDialog(self.panel, "Settings saved successfully!")
        except Exception as e:
            self.status_area.append("\nError saving settings: " + str(e))

    def clear_logs(self, event):
        self.log_data = []
        self.tracking_map = {}
        self.request_counter = 0
        self.status_area.append("\nLogs cleared successfully.")

    def backup_now(self, event):
        self.export_csv(auto=True, is_backup=True)
        self.status_area.append("\nManual backup completed.")

    def getTabCaption(self):
        return "SAVER_LOGGER"

    def getUiComponent(self):
        return self.panel

    # --------------------- HTTP + Export ------------------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            analyzed_request = self._helpers.analyzeRequest(messageInfo)
            analyzed_response = self._helpers.analyzeResponse(messageInfo.getResponse())
            url = str(analyzed_request.getUrl())
            host = messageInfo.getHttpService().getHost()
            method = analyzed_request.getMethod()
            status_code = analyzed_response.getStatusCode()
            tool_name = self._callbacks.getToolName(toolFlag)
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            self.request_counter += 1
            param_count = len(analyzed_request.getParameters()) if tool_name == "Scanner" else 0

            entry = self.tracking_map.get(url, {'request_count': 0, 'start_time': now, 'end_time': now, 'insertion_points': 0})
            entry['request_count'] += 1
            entry['end_time'] = now
            entry['insertion_points'] += param_count
            self.tracking_map[url] = entry

            log_entry = [self.request_counter, host, method, url, status_code, tool_name,
                         entry['request_count'], entry['insertion_points'], entry['start_time'], entry['end_time']]
            self.log_data.append(log_entry)

    def export_csv(self, event=None, auto=False, is_backup=False):
        new_data = self.log_data[self.last_export_count:]
        if not new_data:
            return
        self.last_export_count = len(self.log_data)

        timestamp = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
        if auto:
            path = self.folder_input.getText().strip() if is_backup else os.path.join(os.path.expanduser("~"), "Desktop")
            suffix = "BACKUP_" if is_backup else ""
            filename = os.path.join(path, "SAVER_LOGGER_" + suffix + timestamp + ".csv")
        else:
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Log as CSV")
            if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
                return
            file = chooser.getSelectedFile()
            filename = file.getAbsolutePath()
            if not filename.lower().endswith(".csv"):
                filename += ".csv"

        try:
            fos = FileOutputStream(filename)
            osw = OutputStreamWriter(fos, Charset.forName("UTF-8"))
            writer = BufferedWriter(osw)

            burp_version = self._callbacks.getBurpVersion()
            burp_version_str = " ".join([str(i) for i in burp_version]) if burp_version else "Unknown"
            exported_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            writer.write("# Generated By: SAVER_LOGGER Burp Extension\n")
            writer.write("# Burp Suite Version: %s\n" % burp_version_str)
            writer.write("# Exported Timestamp: %s\n" % exported_time)
            writer.write("# Extension Runtime ID: %s\n" % self.runtime_id)
            writer.write("\n")

            header = ['Serial No', 'Host', 'Request Method', 'URL', 'Status Code', 'Tool Name',
                      'Request Count', 'Insertion Point Count', 'Start Time', 'End Time']
            writer.write(",".join(header) + "\n")

            for row in new_data:
                csv_row = [str(col).replace(",", " ") for col in row]
                writer.write(",".join(csv_row) + "\n")

            writer.close()
            if not auto:
                JOptionPane.showMessageDialog(self.panel, "Log saved successfully at:\n" + filename)
        except Exception as e:
            if not auto:
                JOptionPane.showMessageDialog(self.panel, "Failed to export CSV:\n" + str(e))

    def extensionUnloaded(self):
        if self.backup_timer:
            self.backup_timer.cancel()
        self.export_csv(auto=True)
        print("[SAVER_LOGGER] Logs auto-saved before exit.")
