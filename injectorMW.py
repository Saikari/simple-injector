from Bypass import *
from PyQt6.QtWidgets import QMainWindow, QListWidget, QListWidgetItem, QMessageBox, QFileDialog
import psutil
import ctypes
from PyQt6.QtCore import Qt

class injectorMW(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process List")
        self.injectors = {}
        self.processLW = QListWidget(self)
        self.processlist = [(p.name(), get_class_name(win32gui.FindWindow(None, p.name()))) for p in psutil.process_iter(['name', 'pid']) if p.status() == psutil.STATUS_RUNNING]
        self.processNames = [f'{i[0]}' for i in self.processlist]
        self.classNames = [f'{i[1]}' for i in self.processlist]
        QLWIs = [QListWidgetItem(i, self.processLW) for i in self.processNames]
        for i, item in enumerate(QLWIs):
            item.setData(Qt.UserRole, (self.processlist[i][0], self.processlist[i][1]))
        self.processLW.itemDoubleClicked.connect(self.clickd)
        self.processLW.setSortingEnabled(True)
        self.setCentralWidget(self.processLW)

    def clickd(self, item):
        process_name = item.data(Qt.UserRole)[0]
        class_name = item.data(Qt.UserRole)[1]
        if class_name not in self.injectors:
            fname, _ = QFileDialog.getOpenFileName(self, f'Select .DLL to inject into process {process_name}')
            if fname:
                try:
                    self.injectors[class_name] = Bypass()
                    self.injectors[class_name].load_from_name(process_name)
                    self.injectors[class_name].Attack(fname, process_name, class_name)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f'Failed to inject .DLL {self.injectors[class_name].path.split("/")[-1]} into {process_name}')
                else:
                    QMessageBox.information(self, "Info", f'Successfully injected .DLL {self.injectors[class_name].path.split("/")[-1]} into {process_name}')
        else:
            try:
                self.injectors[class_name].unload()
            except Exception as e:
                QMessageBox.critical(self, "Error", f'Failed to unload .DLL {self.injectors[class_name].path.split("/")[-1]} from {process_name}')
            else:
                QMessageBox.information(self, "Info", f'Successfully unloaded .DLL {self.injectors[class_name].path.split("/")[-1]} from {process_name}')

def get_class_name(hwnd):
    buf_size = 256
    buf = ctypes.create_unicode_buffer(buf_size)
    ctypes.windll.user32.GetClassNameW(hwnd, buf, buf_size)
    return buf.value
