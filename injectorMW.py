from ctypes import create_unicode_buffer
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMainWindow, QListWidget, QListWidgetItem, QMessageBox, QFileDialog
from psutil import process_iter, STATUS_RUNNING
from win32gui import FindWindow

from Bypass import Bypass


class injectorMW(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process List")
        self.injectors = {}
        self.processLW = QListWidget(self)
        self.processlist = [(p.name(), get_class_name(FindWindow(None, p.name()))) for p in
                            process_iter(['name', 'pid']) if p.status() == STATUS_RUNNING]
        self.processNames = [f'{i[0]}' for i in self.processlist]
        self.classNames = [f'{i[1]}' for i in self.processlist]
        QLWIs = [QListWidgetItem(i, self.processLW) for i in self.processNames]
        for i, item in enumerate(QLWIs):
            item.setData(Qt.UserRole, (self.processlist[i][0], self.processlist[i][1]))
        self.processLW.itemDoubleClicked.connect(self.processItemDoubleClickHandler)
        self.processLW.setSortingEnabled(True)
        self.setCentralWidget(self.processLW)

    def processItemDoubleClickHandler(self, item):
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
                    QMessageBox.critical(self, "Error",
                                         f'{e} Failed to inject .DLL '
                                         f'{self.injectors[class_name].path.split("/")[-1]} into {process_name}')
                else:
                    QMessageBox.information(self, "Info",
                                            f'Successfully injected .DLL '
                                            f'{self.injectors[class_name].path.split("/")[-1]} into {process_name}')
        else:
            try:
                self.injectors[class_name].unload()
            except Exception as e:
                QMessageBox.critical(self, "Error",
                                     f'{e} Failed to unload .DLL '
                                     f'{self.injectors[class_name].path.split("/")[-1]} from {process_name}')
            else:
                QMessageBox.information(self, "Info",
                                        f'Successfully unloaded .DLL '
                                        f'{self.injectors[class_name].path.split("/")[-1]} from {process_name}')


def get_class_name(hwnd):
    buf_size = 256
    buf = create_unicode_buffer(buf_size)
    windll.user32.GetClassNameW(hwnd, buf, buf_size)
    return buf.value
