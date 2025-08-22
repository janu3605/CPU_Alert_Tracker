import sys
import time
import psutil
from PyQt5 import QtCore, QtWidgets, QtGui
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import qdarkstyle

CPU_ALERT_THRESHOLD = 80
TOP_N = 3
IGNORED_PIDS = {0, 4}
IGNORED_NAMES = {'System Idle Process', 'System'}

def get_top_processes(n=3):
    # Prime cpu_percent to avoid initial zeros
    for p in psutil.process_iter(['pid', 'name']):
        try:
            _ = p.cpu_percent(interval=None)
        except:
            continue
    time.sleep(0.8)
    proc_list = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.pid in IGNORED_PIDS or p.name() in IGNORED_NAMES:
                continue
            cpu = p.cpu_percent(interval=None)
            proc_list.append((cpu, p.pid, p.name()))
        except:
            continue
    proc_list.sort(reverse=True)
    return proc_list[:n]

class CPUGraph(QtWidgets.QWidget):
    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"CPU Usage Graph (PID: {pid})")
        self.setGeometry(150, 150, 500, 350)
        self.fig, self.ax = plt.subplots(figsize=(5, 2.5), tight_layout=True)
        self.canvas = FigureCanvas(self.fig)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.canvas)
        self.setLayout(layout)

        self.cpu_data = []
        self.time_data = []

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)  # update every second

        # Drag/resize lag fix timer
        self._drag_resize_timer = QtCore.QTimer(self)
        self._drag_resize_timer.setSingleShot(True)
        self._drag_resize_timer.timeout.connect(self._resume_timer)

        self.start_time = time.time()
        self.pid = pid

        self.setAttribute(QtCore.Qt.WA_DeleteOnClose)

    def moveEvent(self, event):
        self._pause_timer()
        self._drag_resize_timer.start(1000)
        super().moveEvent(event)

    def resizeEvent(self, event):
        self._pause_timer()
        self._drag_resize_timer.start(1000)
        super().resizeEvent(event)

    def _pause_timer(self):
        if self.timer.isActive():
            self.timer.stop()

    def _resume_timer(self):
        if not self.timer.isActive():
            self.timer.start(1000)

    def refresh(self):
        try:
            p = psutil.Process(self.pid)
            cpu = p.cpu_percent(interval=1)
            self.cpu_data.append(cpu)
            self.time_data.append(time.time() - self.start_time)
            if len(self.cpu_data) > 60:
                self.cpu_data = self.cpu_data[-60:]
                self.time_data = self.time_data[-60:]
            self.ax.clear()
            self.ax.plot(self.time_data, self.cpu_data, color='orange')
            self.ax.set_title(f"CPU % for PID {self.pid}")
            self.ax.set_ylim(0, 100)
            self.ax.set_xlabel("Seconds")
            self.ax.set_ylabel("CPU %")
            self.canvas.draw()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.timer.stop()
            self.close()

class ProcessMonitorApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process Monitoring IDS (Windows)")
        self.setGeometry(100, 100, 950, 500)
        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

        # Delay timer for resuming updates after drag/resize (to reduce lag)
        self._drag_resize_timer = QtCore.QTimer(self)
        self._drag_resize_timer.setSingleShot(True)
        self._drag_resize_timer.timeout.connect(self._resume_updates)

        layout = QtWidgets.QVBoxLayout(self)
        title = QtWidgets.QLabel("Process Monitoring Intrusion Detection System")
        title.setAlignment(QtCore.Qt.AlignCenter)
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        self.status_label = QtWidgets.QLabel("Monitoring top processes...")
        layout.addWidget(self.status_label)

        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["PID", "Process Name", "CPU %", "Mem (MB)", "Alert", "Action"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.table.cellDoubleClicked.connect(self.show_graph)
        layout.addWidget(self.table)

        # System Tray Setup
        self.tray_icon = QtWidgets.QSystemTrayIcon(self)
        # Save your default icon (use the current icon or fallback)
        self._default_icon = self.tray_icon.icon()
        if self._default_icon.isNull():
            self._default_icon = self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon)

        # Load your local alert icon file (make sure this file exists next to your script)
        self._alert_icon = QtGui.QIcon('alert_dot.png')

        self.tray_icon.setIcon(self._default_icon)
        self.tray_icon.setVisible(True)
        self.tray_icon.setToolTip("Process Monitoring IDS")

        tray_menu = QtWidgets.QMenu()
        tray_menu.addAction("Restore", self.show)
        tray_menu.addAction("Quit", QtWidgets.qApp.quit)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_trayicon_activated)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh_top_processes)
        self.timer.start(5000)  # Update every 5 seconds

        self.refresh_top_processes()
        self.show()

    def on_trayicon_activated(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.Trigger:
            self.showNormal()
            self.activateWindow()

    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            # If window is minimized
            if self.isMinimized():
                # Only show notification if alert present
                if self._alert_icon is not None and self.tray_icon.icon().cacheKey() == self._alert_icon.cacheKey():
                    self.tray_icon.showMessage(
                        "Minimized",
                        "Process Monitoring IDS is minimized (ALERT active).",
                        QtWidgets.QSystemTrayIcon.Information,
                        3000
                    )
                # Hide window on minimize to tray
                QtCore.QTimer.singleShot(0, self.hide)
        super().changeEvent(event)

    def closeEvent(self, event):
        # On close, hide window instead of quitting, only hide silently
        event.ignore()
        self.hide()


    # Pause update timer on move/resize start and resume later to reduce lag
    def moveEvent(self, event):
        self._pause_updates()
        self._drag_resize_timer.start(1000)  # resume updates 1s after move ends
        super().moveEvent(event)

    def resizeEvent(self, event):
        self._pause_updates()
        self._drag_resize_timer.start(1000)  # resume updates 1s after resize ends
        super().resizeEvent(event)

    def _pause_updates(self):
        if self.timer.isActive():
            self.timer.stop()

    def _resume_updates(self):
        if not self.timer.isActive():
            self.timer.start(5000)

    def refresh_top_processes(self):
        procs = get_top_processes(TOP_N)
        alert_found = False
        self.table.setRowCount(0)
        for cpu, pid, name in procs:
            try:
                proc = psutil.Process(pid)
                mem = proc.memory_info().rss / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                mem = 0
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(pid)))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(name))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(f"{cpu:.2f}"))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{mem:.2f}"))

            alert_item = QtWidgets.QTableWidgetItem("ALERT!" if cpu > CPU_ALERT_THRESHOLD else "")
            if cpu > CPU_ALERT_THRESHOLD:
                alert_found = True
                alert_item.setForeground(QtGui.QBrush(QtGui.QColor('red')))
            self.table.setItem(row, 4, alert_item)

            btn = QtWidgets.QPushButton("Terminate")
            btn.clicked.connect(lambda _, pid=pid: self.terminate_process(pid))
            self.table.setCellWidget(row, 5, btn)

        # Update tray icon and tooltip based on alerts
        if alert_found:
            self.tray_icon.setIcon(self._alert_icon)
            self.tray_icon.setToolTip("Process Monitoring IDS - ALERT")
        else:
            self.tray_icon.setIcon(self._default_icon)
            self.tray_icon.setToolTip("Process Monitoring IDS")

    def terminate_process(self, pid):
        try:
            proc = psutil.Process(pid)
            answer = QtWidgets.QMessageBox.question(
                self, "Confirm Termination",
                f"Are you sure you want to terminate {proc.name()} (PID {pid})?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if answer == QtWidgets.QMessageBox.Yes:
                proc.terminate()
                proc.wait(timeout=3)
                QtWidgets.QMessageBox.information(self, "Terminated", f"Process {pid} terminated.")
            self.refresh_top_processes()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

    def show_graph(self, row, _column):
        pid_item = self.table.item(row, 0)
        if not pid_item:
            return
        pid = int(pid_item.text())
        self.graph_win = CPUGraph(pid)
        self.graph_win.show()


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    window = ProcessMonitorApp()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
