# encoding: utf-8
from burp import IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, ITab
from javax.swing import JPanel, JButton, JFileChooser, JTextPane, JScrollPane, JOptionPane
from java.awt import BorderLayout
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter
from java.nio.charset import Charset
import uuid
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

        # Runtime values
        self.runtime_id = str(uuid.uuid4())
        self.burp_version = self._get_burp_version()

        self._init_ui()
        self._callbacks.addSuiteTab(self)

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        info_html = (
            "<html><body style='font-size:12px;'>"
            "<h2 style='color:orange;'>Extension: SAVER_LOGGER</h2>"
            "<b>Author:</b> Sachhit Anasane<br><br>"
            "<b>Features:</b><ul>"
            "<li>Logs every HTTP request from all Burp Suite Tabs</li>"
            "<li>Tracks request count, insertion points (approx.), timestamps</li>"
            "<li>Auto-saves log on shutdown (File Location : Desktop)</li>"
            "<li>Export to formatted CSV</li></ul><br>"
            "<b>Instructions:</b><br>Use Burp Suite as required normally.<br>Click <i>Export Log as CSV</i> to save the Logs.<br><br><br>To disable logger, simply turn off the extension from extensions tab.<br>"
            "</body></html>"
        )

        self.info_area = JTextPane()
        self.info_area.setContentType("text/html")
        self.info_area.setText(info_html)
        self.info_area.setEditable(False)
        scroll_pane = JScrollPane(self.info_area)
        self.panel.add(scroll_pane, BorderLayout.CENTER)

        self.export_button = JButton("Export Log as CSV", actionPerformed=self.export_csv)
        self.panel.add(self.export_button, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "SAVER_LOGGER"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            analyzed_request = self._helpers.analyzeRequest(messageInfo)
            analyzed_response = self._helpers.analyzeResponse(messageInfo.getResponse())

            url = str(analyzed_request.getUrl())
            method = analyzed_request.getMethod()
            host = messageInfo.getHttpService().getHost()
            status_code = analyzed_response.getStatusCode()
            tool_name = self._callbacks.getToolName(toolFlag)
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            self.request_counter += 1
            param_count = len(analyzed_request.getParameters()) if tool_name == "Scanner" else 0

            entry = self.tracking_map.get(url, {
                'request_count': 0,
                'start_time': now,
                'end_time': now,
                'insertion_points': 0,
                'host': host,
                'method': method,
                'tool_name': tool_name,
                'status_code': status_code
            })

            entry['request_count'] += 1
            entry['end_time'] = now
            entry['insertion_points'] += param_count
            self.tracking_map[url] = entry

            self.log_data.append([
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
            ])

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
                'insertion_points': insertion_point_count,
                'host': 'unknown',
                'method': 'UNKNOWN',
                'tool_name': 'Unknown',
                'status_code': '-'
            }

    def export_csv(self, event=None, auto=False):
        if auto:
            timestamp = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            filename = os.path.join(desktop, "SAVER_LOGGER_" + timestamp + ".csv")
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

            header = [
                'Serial No', 'Host', 'Request Method', 'URL', 'Status Code',
                'Tool Name', 'Request Count', 'Insertion Point Count', 'Start Time', 'End Time'
            ]
            writer.write(",".join(header) + "\n")

            for row in self.log_data:
                csv_row = [str(col).replace(",", " ") for col in row]
                writer.write(",".join(csv_row) + "\n")

            # Append metadata proof block
            writer.write("# Generated By: SAVER_LOGGER Burp Extension\n")
            writer.write("# Burp Suite Version: " + self.burp_version + "\n")
            writer.write("# Exported Timestamp: " + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
            writer.write("# Extension Runtime ID: " + self.runtime_id + "\n")

            writer.close()

            if not auto:
                JOptionPane.showMessageDialog(self.panel, "Log saved successfully at:\n" + filename)

        except Exception as e:
            if not auto:
                JOptionPane.showMessageDialog(self.panel, "Failed to export CSV:\n" + str(e))

    def extensionUnloaded(self):
        existing_urls = set(row[3] for row in self.log_data)  # column 3 is URL

        for url, entry in self.tracking_map.items():
            if url in existing_urls:
                continue

            self.request_counter += 1

            self.log_data.append([
                self.request_counter,
                entry.get('host', 'unknown'),
                entry.get('method', 'UNKNOWN'),
                url,
                entry.get('status_code', '-'),
                entry.get('tool_name', 'Unknown'),
                entry.get('request_count', 0),
                entry.get('insertion_points', 0),
                entry.get('start_time', ''),
                entry.get('end_time', '')
            ])

        self.export_csv(auto=True)
        print("[SAVER_LOGGER] Logs auto-saved before exit.")

    def _get_burp_version(self):
        try:
            version_info = self._callbacks.getBurpVersion()
            return version_info[0] + " " + version_info[1] + "." + version_info[2]
        except:
            return "Unknown"
