import sys
import psutil
import csv
import time
from PyQt5 import QtCore, QtWidgets, QtGui

# Function to monitor process activity
def monitor_process_activity(pid):
    """ Monitor the activities of a process using psutil. """
    try:
        process = psutil.Process(pid)
        process_info = []

        # Add headings in bold with corresponding details
        process_info.append(f"<b>Process Name:</b> {process.name()}")
        process_info.append(f"<b>Process Status:</b> {process.status()}")

        # Get CPU and memory usage
        cpu_usage = process.cpu_percent(interval=0.1)
        memory_usage = process.memory_info().rss / (1024 * 1024)

        # Highlight CPU usage if it exceeds a threshold
        if cpu_usage > 80:
            process_info.append(
                f"<b>CPU Usage:</b> <span style='color:red; font-weight:bold;'>ALERT: High CPU Usage ({cpu_usage:.2f}%)</span>"
            )
        else:
            process_info.append(f"<b>CPU Usage:</b> {cpu_usage:.2f}%")
        process_info.append(f"<b>Memory Usage:</b> {memory_usage:.2f} MB")

        # Include open files
        open_files = process.open_files()
        for file in open_files:
            process_info.append(f"<b>File Accessed:</b> {file.path}")

        # Include child processes
        children = process.children(recursive=True)
        for child in children:
            process_info.append(f"<b>Child Process Executed:</b> {child.name()}")

        return process_info
    except psutil.NoSuchProcess:
        return ["<b>Error:</b> Process not found."]
    except psutil.AccessDenied:
        return ["<b>Error:</b> Access denied to the process."]
    except Exception as e:
        return [f"<b>Error:</b> {str(e)}"]


# Thread for periodic monitoring
class MonitorThread(QtCore.QThread):
    update_signal = QtCore.pyqtSignal(list)

    def __init__(self, pid, parent=None):
        super(MonitorThread, self).__init__(parent)
        self.pid = pid
        self.running = True

    def run(self):
        """ Periodically monitor the process. """
        while self.running:
            process_info = monitor_process_activity(self.pid)
            self.update_signal.emit(process_info)
            time.sleep(5)  # Wait 5 seconds between updates

# Main Window Class for PyQt5
class ProcessMonitorApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Process Monitoring IDS (Windows)")
        self.setGeometry(100, 100, 800, 600)

        # Main Layout
        layout = QtWidgets.QVBoxLayout()

        # Title
        title_label = QtWidgets.QLabel("Process Monitoring Intrusion Detection System")
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        title_font = QtGui.QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)

        # Process ID input section
        pid_layout = QtWidgets.QHBoxLayout()
        pid_label = QtWidgets.QLabel("Enter Process ID:")
        pid_label.setFont(QtGui.QFont("Arial", 12, QtGui.QFont.Bold))
        self.pid_input = QtWidgets.QLineEdit(self)
        self.pid_input.setPlaceholderText("e.g., 1234")
        self.pid_input.setFont(QtGui.QFont("Arial", 12))

        pid_layout.addWidget(pid_label)
        pid_layout.addWidget(self.pid_input)

        layout.addLayout(pid_layout)

        # Start Monitoring Button
        start_button = QtWidgets.QPushButton("Start Monitoring", self)
        start_button.setStyleSheet("background-color: #4CAF50; color: white; border-radius: 5px; padding: 10px;")
        start_button.setFont(QtGui.QFont("Arial", 12, QtGui.QFont.Bold))
        start_button.clicked.connect(self.start_monitoring_button_clicked)

        # Center the button
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(start_button, alignment=QtCore.Qt.AlignCenter)
        layout.addLayout(button_layout)

        # Status label
        self.status_label = QtWidgets.QLabel("Waiting for Process ID...")
        self.status_label.setFont(QtGui.QFont("Arial", 11))
        layout.addWidget(self.status_label)

        # Monitored Data Area with Curved Borders and Background
        self.monitored_data_frame = QtWidgets.QFrame(self)
        self.monitored_data_frame.setStyleSheet("""
            background-color: #f0f0f0; 
            border: 1px solid #ccc; 
            border-radius: 15px; 
            padding: 10px;
        """)
        self.monitored_data_frame_layout = QtWidgets.QVBoxLayout(self.monitored_data_frame)
        
        self.text_area = QtWidgets.QTextEdit(self.monitored_data_frame)
        self.text_area.setReadOnly(True)
        self.text_area.setStyleSheet("""
            background-color: #f4f4f4; 
            border-radius: 10px; 
            padding: 10px;
        """)

        # Set larger font for the text area
        font = QtGui.QFont()
        font.setPointSize(11)
        self.text_area.setFont(font)

        self.monitored_data_frame_layout.addWidget(self.text_area)
        layout.addWidget(self.monitored_data_frame)

        self.setLayout(layout)

    def start_monitoring_button_clicked(self):
        """ Handle the click event for the Start Monitoring button. """
        pid = self.pid_input.text()
        self.start_monitoring(pid)

    def start_monitoring(self, pid):
        """ Start the process monitoring in a separate thread. """
        try:
            pid = int(pid)  # Get the process ID from the entry box
            self.status_label.setText("Starting Monitoring...")

            # Clear the text area to refresh the display
            self.text_area.clear()

            # Stop any existing monitoring threads
            if hasattr(self, 'monitor_thread') and self.monitor_thread.isRunning():
                self.monitor_thread.running = False
                self.monitor_thread.wait()

            # Create and start the monitoring thread
            self.monitor_thread = MonitorThread(pid)
            self.monitor_thread.update_signal.connect(self.update_gui)
            self.monitor_thread.start()
        except ValueError:
            QtWidgets.QMessageBox.critical(None, "Error", "Please enter a valid process ID.")

    def update_gui(self, process_info):
        """ Update the GUI with process info. """
        self.text_area.clear()
        for info in process_info:
            self.text_area.append(info)

# Main function to run the PyQt5 application
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = ProcessMonitorApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
