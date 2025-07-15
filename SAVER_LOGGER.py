# encoding: utf-8
from burp import IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab
from javax.swing import (JPanel, JButton, JFileChooser, JTextPane, JScrollPane, JOptionPane,
                         JCheckBox, JLabel, JTextField, BoxLayout, JSplitPane, JFileChooser,
                         JTabbedPane, BorderFactory, SwingConstants, JTextArea, JTable,
                         JComboBox, JSpinner, SpinnerNumberModel)
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel
from java.awt import BorderLayout, Dimension, Color, Font, GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.awt.event import ActionListener
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter
from java.nio.charset import Charset
import datetime
import os
import threading
import time

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

        self.auto_backup_enabled = True
        self.backup_interval = 60  # seconds
        self.auto_backup_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.backup_thread = None

        self._init_ui()
        self._callbacks.addSuiteTab(self)
        self._start_backup_thread()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())
        
        # Create tabbed pane
        self.tabbed_pane = JTabbedPane()
        
        # Create tabs
        self._create_dashboard_tab()
        self._create_settings_tab()
        
        self.panel.add(self.tabbed_pane, BorderLayout.CENTER)

    def _create_dashboard_tab(self):
        dashboard_panel = JPanel(BorderLayout())
        dashboard_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Header panel
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        header_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0))
        
        title_label = JLabel("SAVER_LOGGER - Store All Logs")
        title_label.setFont(Font("Arial", Font.BOLD, 28))
        title_label.setForeground(Color(0, 100, 0))
        header_panel.add(title_label)
        
        dashboard_panel.add(header_panel, BorderLayout.NORTH)
        
        # Main content panel
        main_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        # Quick actions panel
        actions_panel = self._create_quick_actions_panel()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(5, 5, 5, 5)
        main_panel.add(actions_panel, gbc)
        
        dashboard_panel.add(main_panel, BorderLayout.CENTER)
        
        self.tabbed_pane.addTab("Dashboard", dashboard_panel)

    def _create_stats_panel(self):
        stats_panel = JPanel(BorderLayout())
        stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        
        # Create stats info area
        stats_info = JTextPane()
        stats_info.setContentType("text/html")
        stats_info.setEditable(False)
        stats_info.setBackground(Color(248, 248, 248))
        
        # Update stats (this would be called periodically)
        self._update_stats_display(stats_info)
        
        stats_scroll = JScrollPane(stats_info)
        stats_scroll.setPreferredSize(Dimension(600, 150))
        stats_panel.add(stats_scroll, BorderLayout.CENTER)
        
        return stats_panel

    def _update_stats_display(self, stats_info):
        stats_html = """
        <html>
        <body style='font-family: Arial, sans-serif; font-size: 12px; margin: 10px;'>
        <table border='0' cellpadding='8' cellspacing='0' width='100%'>
        <tr>
            <td style='background-color: #e6f3ff; padding: 8px; border-radius: 4px;'>
                <b>Total Requests:</b> {total_requests}
            </td>
            <td style='background-color: #f0f8e6; padding: 8px; border-radius: 4px;'>
                <b>Unique URLs:</b> {unique_urls}
            </td>
        </tr>
        <tr>
            <td style='background-color: #fff2e6; padding: 8px; border-radius: 4px;'>
                <b>Runtime ID:</b> {runtime_id}
            </td>
            <td style='background-color: #f8f0ff; padding: 8px; border-radius: 4px;'>
                <b>Auto Backup:</b> {backup_status}
            </td>
        </tr>
        </table>
        </body>
        </html>
        """.format(
            total_requests=self.request_counter,
            unique_urls=len(self.tracking_map),
            runtime_id=self.runtime_id,
            backup_status="Enabled" if self.auto_backup_enabled else "Disabled"
        )
        stats_info.setText(stats_html)

    def _create_quick_actions_panel(self):
        actions_panel = JPanel(BorderLayout())
        actions_panel.setBorder(BorderFactory.createTitledBorder("Quick Actions"))
        
        # Create action buttons panel
        buttons_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
        
        # Export button
        export_btn = JButton("Export CSV")
        export_btn.setPreferredSize(Dimension(120, 35))
        export_btn.addActionListener(self.export_csv)
        buttons_panel.add(export_btn)
        
        # Clear logs button
        clear_btn = JButton("Clear Logs")
        clear_btn.setPreferredSize(Dimension(120, 35))
        clear_btn.addActionListener(self.clear_logs)
        buttons_panel.add(clear_btn)
        
        # Backup now button
        backup_btn = JButton("Backup Now")
        backup_btn.setPreferredSize(Dimension(120, 35))
        backup_btn.addActionListener(self.backup_now)
        buttons_panel.add(backup_btn)
        
        actions_panel.add(buttons_panel, BorderLayout.NORTH)
        
        # Info area with features and instructions
        info_area = JTextPane()
        info_area.setContentType("text/html")
        info_area.setEditable(False)
        info_area.setBackground(Color(250, 250, 250))
        
        info_html = """
        <html>
        <body style='font-family: Arial, sans-serif; font-size: 13px; margin: 15px; line-height: 1.6;'>
        
        <h2 style='color: #ff6600; margin-bottom: 10px; font-size: 16px;'>SAVER_LOGGER DETAILS</h2>
        <p style='margin-bottom: 15px;'><strong>Author:</strong> Sachhit Anasane</p>
        
        <h3 style='color: #333; margin-bottom: 8px; font-size: 14px;'>Features:</h3>
        <ul style='margin-left: 20px; margin-bottom: 15px;'>
        <li>Logs every HTTP request from all Burp Suite Tabs</li>
        <li>Tracks request count, insertion points, timestamps</li>
        <li>Auto-saves log file on crash / accidental closures (On Desktop)</li>
        <li>Optional interval-based auto-backups to custom path</li>
        <li>Export to formatted CSV manually</li>
        </ul>
        
        <h3 style='color: #333; margin-bottom: 8px; font-size: 14px;'>Instructions:</h3>
        <p style='margin-bottom: 8px;'>Use Burp Suite normally.</p>
        <p style='margin-bottom: 8px;'>Click <em>Export CSV </em> to save log file manually.</p>
        <p style='margin-bottom: 8px;'>Click <em>Clear Logs </em> to clear all the logs.</p>
        <p style='margin-bottom: 8px;'>Click <em>Backup Now </em> for instant backup log file.</p>
        <p style='margin-bottom: 15px;'>To disable logger, simply turn off the extension from extensions tab.</p>
        
        </body>
        </html>
        """
        info_area.setText(info_html)
        
        info_scroll = JScrollPane(info_area)
        info_scroll.setPreferredSize(Dimension(600, 300))
        actions_panel.add(info_scroll, BorderLayout.CENTER)
        
        return actions_panel

    def _create_settings_tab(self):
        settings_panel = JPanel(BorderLayout())
        settings_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Settings form panel
        form_panel = JPanel(GridBagLayout())
        form_panel.setBorder(BorderFactory.createTitledBorder("Backup Configuration"))
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        # Auto backup checkbox with action listener
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        self.enable_backup = JCheckBox("Enable Automatic Backup", True)
        self.enable_backup.addActionListener(self.on_backup_toggle)
        form_panel.add(self.enable_backup, gbc)
        
        # Backup interval
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 1
        form_panel.add(JLabel("Backup Interval (seconds):"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 1
        self.interval_spinner = JSpinner(SpinnerNumberModel(60, 10, 3600, 10))
        self.interval_spinner.setPreferredSize(Dimension(100, 25))
        form_panel.add(self.interval_spinner, gbc)
        
        # Backup folder
        gbc.gridx = 0
        gbc.gridy = 2
        form_panel.add(JLabel("Backup Folder:"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.folder_input = JTextField(self.auto_backup_path)
        self.folder_input.setPreferredSize(Dimension(300, 25))
        form_panel.add(self.folder_input, gbc)
        
        # Browse button
        gbc.gridx = 2
        gbc.gridy = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        self.browse_button = JButton("Browse")
        self.browse_button.addActionListener(self.select_folder)
        form_panel.add(self.browse_button, gbc)
        
        # Save settings button
        gbc.gridx = 0
        gbc.gridy = 3
        gbc.gridwidth = 3
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        save_btn = JButton("Save Settings")
        save_btn.addActionListener(self.save_settings)
        form_panel.add(save_btn, gbc)
        
        settings_panel.add(form_panel, BorderLayout.NORTH)
        
        # Status panel
        status_panel = JPanel(BorderLayout())
        status_panel.setBorder(BorderFactory.createTitledBorder("Status"))
        
        self.status_area = JTextArea(10, 50)
        self.status_area.setEditable(False)
        self.status_area.setBackground(Color(245, 245, 245))
        self.status_area.setText("Extension loaded successfully.\nAuto-backup thread started.\nReady to log HTTP requests.")
        
        status_scroll = JScrollPane(self.status_area)
        status_panel.add(status_scroll, BorderLayout.CENTER)
        
        settings_panel.add(status_panel, BorderLayout.CENTER)
        
        self.tabbed_pane.addTab("Autobackup Settings", settings_panel)

    def on_backup_toggle(self, event):
        if self.enable_backup.isSelected():
            self.status_area.append("\nAuto-backup enabled.")
        else:
            self.status_area.append("\nAuto-backup thread stopped.")

    def _create_stats_panel(self):
        stats_panel = JPanel(BorderLayout())
        stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        
        # Create stats info area
        stats_info = JTextPane()
        stats_info.setContentType("text/html")
        stats_info.setEditable(False)
        stats_info.setBackground(Color(248, 248, 248))
        
        # Update stats (this would be called periodically)
        self._update_stats_display(stats_info)
        
        stats_scroll = JScrollPane(stats_info)
        stats_scroll.setPreferredSize(Dimension(600, 150))
        stats_panel.add(stats_scroll, BorderLayout.CENTER)
        
        return stats_panel

    def _update_stats_display(self, stats_info):
        stats_html = """
        <html>
        <body style='font-family: Arial, sans-serif; font-size: 12px; margin: 10px;'>
        <table border='0' cellpadding='8' cellspacing='0' width='100%'>
        <tr>
            <td style='background-color: #e6f3ff; padding: 8px; border-radius: 4px;'>
                <b>Total Requests:</b> {total_requests}
            </td>
            <td style='background-color: #f0f8e6; padding: 8px; border-radius: 4px;'>
                <b>Unique URLs:</b> {unique_urls}
            </td>
        </tr>
        <tr>
            <td style='background-color: #fff2e6; padding: 8px; border-radius: 4px;'>
                <b>Runtime ID:</b> {runtime_id}
            </td>
            <td style='background-color: #f8f0ff; padding: 8px; border-radius: 4px;'>
                <b>Auto Backup:</b> {backup_status}
            </td>
        </tr>
        </table>
        </body>
        </html>
        """.format(
            total_requests=self.request_counter,
            unique_urls=len(self.tracking_map),
            runtime_id=self.runtime_id,
            backup_status="Enabled" if self.auto_backup_enabled else "Disabled"
        )
        stats_info.setText(stats_html)

    def select_folder(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Select Auto Backup Folder")
        user_selection = chooser.showOpenDialog(self.panel)
        if user_selection == JFileChooser.APPROVE_OPTION:
            selected_folder = chooser.getSelectedFile().getAbsolutePath()
            self.folder_input.setText(selected_folder)

    def save_settings(self, event):
        try:
            self.auto_backup_enabled = self.enable_backup.isSelected()
            self.backup_interval = int(self.interval_spinner.getValue())
            self.auto_backup_path = self.folder_input.getText().strip()
            
            self.status_area.append("\nSettings saved successfully.")
            JOptionPane.showMessageDialog(self.panel, "Settings saved successfully!")
        except Exception as e:
            self.status_area.append("\nError saving settings: " + str(e))
            JOptionPane.showMessageDialog(self.panel, "Error saving settings: " + str(e))

    def clear_logs(self, event):
        result = JOptionPane.showConfirmDialog(
            self.panel,
            "Are you sure you want to clear all logs?",
            "Clear Logs",
            JOptionPane.YES_NO_OPTION
        )
        if result == JOptionPane.YES_OPTION:
            self.log_data = []
            self.tracking_map = {}
            self.request_counter = 0
            self.refresh_table(None)
            self.status_area.append("\nLogs cleared successfully.")

    def backup_now(self, event):
        self.export_csv(auto=True, is_backup=True)
        self.status_area.append("\nManual backup completed.")

    def refresh_table(self, event):
        # Clear existing rows
        self.table_model.setRowCount(0)
        
        # Add data to table
        for row in self.log_data:
            self.table_model.addRow(row)

    def clear_table(self, event):
        self.table_model.setRowCount(0)

    def getTabCaption(self):
        return "SAVER_LOGGER"

    def getUiComponent(self):
        return self.panel

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

            entry = self.tracking_map.get(url, {
                'request_count': 0,
                'start_time': now,
                'end_time': now,
                'insertion_points': 0
            })

            entry['request_count'] += 1
            entry['end_time'] = now
            entry['insertion_points'] += param_count
            self.tracking_map[url] = entry

            log_entry = [
                self.request_counter,
                host,
                method,
                url,
                status_code,
                tool_name,
                entry['request_count'],
                entry['insertion_points'],
                entry['start_time'],
                entry['end_time']
            ]
            
            self.log_data.append(log_entry)

    def newScanIssue(self, issue):
        url = issue.getUrl().toString()
        insertion_point_count = 0
        for http_msg in issue.getHttpMessages():
            request_info = self._helpers.analyzeRequest(http_msg)
            insertion_point_count += len(request_info.getParameters())

        if url in self.tracking_map:
            self.tracking_map[url]['insertion_points'] += insertion_point_count
        else:
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.tracking_map[url] = {
                'request_count': 0,
                'start_time': now,
                'end_time': now,
                'insertion_points': insertion_point_count
            }

    def _start_backup_thread(self):
        def backup_loop():
            while getattr(threading.currentThread(), "running", True):
                try:
                    if self.enable_backup.isSelected():
                        interval = int(self.interval_spinner.getValue())
                        time.sleep(interval)
                        self.export_csv(auto=True, is_backup=True)
                    else:
                        time.sleep(5)
                except Exception:
                    break

        self.backup_thread = threading.Thread(target=backup_loop, name="AutoBackupThread")
        self.backup_thread.setDaemon(True)
        self.backup_thread.running = True
        self.backup_thread.start()

    def export_csv(self, event=None, auto=False, is_backup=False):
        timestamp = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
        if auto:
            path = self.folder_input.getText().strip() if is_backup else os.path.join(os.path.expanduser("~"), "Desktop")
            suffix = "BACKUP_" if is_backup else ""
            filename = os.path.join(path, "SAVER_LOGGER_" + suffix + timestamp + ".csv")
        else:
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Log as CSV")
            user_selection = chooser.showSaveDialog(self.panel)
            if user_selection != JFileChooser.APPROVE_OPTION:
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

            header = [
                'Serial No', 'Host', 'Request Method', 'URL', 'Status Code', 'Tool Name',
                'Request Count', 'Insertion Point Count', 'Start Time', 'End Time'
            ]
            writer.write(",".join(header) + "\n")

            for row in self.log_data:
                csv_row = [str(col).replace(",", " ") for col in row]
                writer.write(",".join(csv_row) + "\n")

            writer.close()
            if not auto:
                JOptionPane.showMessageDialog(self.panel, "Log saved successfully at:\n" + filename)
                if hasattr(self, 'status_area'):
                    self.status_area.append("\nCSV exported to: " + filename)

        except Exception as e:
            if not auto:
                JOptionPane.showMessageDialog(self.panel, "Failed to export CSV:\n" + str(e))
            if hasattr(self, 'status_area'):
                self.status_area.append("\nError exporting CSV: " + str(e))

    def extensionUnloaded(self):
        if self.backup_thread:
            self.backup_thread.running = False
        self.export_csv(auto=True)
        print("[SAVER_LOGGER] Logs auto-saved before exit.")