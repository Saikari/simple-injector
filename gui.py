from Bypass import *
from PyQt6.QtWidgets import QMainWindow, QListWidget, QListWidgetItem, QMessageBox, QFileDialog
import psutil
from re import findall

class injectorMW(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process List")
        self.injectors = {}
        self.processLW = QListWidget(self)
        self.processlist = [(p.name(), p.pid) for p in psutil.process_iter(['name', 'pid']) if p.status() == psutil.STATUS_RUNNING]
        self.processNames = [f'{i[0]}\tPID:{i[1]}' for i in self.processlist]
        QLWIs = [QListWidgetItem(i, self.processLW) for i in self.processNames]
        self.processLW.itemDoubleClicked.connect(self.clickd)
        self.processLW.setSortingEnabled(True)
        self.setCentralWidget(self.processLW)

    def clickd(self, item):
        pid = findall(r"PID:(.{1,7})", item.text())[0]
        if pid not in self.injectors:
            fname, _ = QFileDialog.getOpenFileName(self, f'Select .DLL to inject into process {item.text()}')
            if fname:
                try:
                    self.injectors[pid] = Injector()
                    self.injectors[pid].load_from_pid(int(pid))
                    self.injectors[pid].inject_dll(fname)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f'Failed to inject .DLL {self.injectors[pid].path.split("/")[-1]} into {item.text()}')
                else:
                    QMessageBox.information(self, "Info", f'Successfully injected .DLL {self.injectors[pid].path.split("/")[-1]} into {item.text()}')
        else:
            try:
                self.injectors[pid].unload()
            except Exception as e:
                QMessageBox.critical(self, "Error", f'Failed to unload .DLL {self.injectors[pid].path.split("/")[-1]} from {item.text()}')
            else:
                QMessageBox.information(self, "Info", f'Successfully unloaded .DLL {self.injectors[pid].path.split("/")[-1]} from {item.text()}')
