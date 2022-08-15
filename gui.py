from Inject import *
from subprocess import PIPE, check_output, STDOUT
from PyQt6.QtWidgets import QMainWindow, QListWidget, QListWidgetItem, QMessageBox, QFileDialog
from re import findall
# Подкласс QMainWindow для настройки главного окна приложения
class injectorMW(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process List")
        self.injectors = {}
        self.processLW = QListWidget(self)
        self.text = check_output('chcp 65001 & tasklist /FI "Status eq Running" /FO CSV', shell=True, stderr=STDOUT).decode('utf-8').splitlines()[2:]
        print(self.text)
        self.processlist = [(ProcessName[1:-1], PID[1:-1]) for 
        ProcessName, PID, _, _, _ in [x.split(',')
        for x in self.text]]
        print(self.processlist)
        self.processNames = [f'{i[0]}\tPID:{i[1]}' for i in self.processlist]
        print(self.processNames)
        QLWIs =  [QListWidgetItem(i, self.processLW) for i in self.processNames]
        self.processLW.itemDoubleClicked.connect(self.clickd)
        self.processLW.setSortingEnabled(True)
        self.setCentralWidget(self.processLW)

    def clickd(self, item):
        pid = findall(r"PID:(.{1,7})", item.text())[0]
        if pid not in self.injectors:
            fname = QFileDialog.getOpenFileName(self, f'Select .DLL to inject into process {item.text()}')[0]
            print(fname)
            if fname:
                try:
                    self.injectors[pid] = Injector()
                    self.injectors[pid].load_from_pid(int(pid))
                    self.injectors[pid].inject_dll(fname)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f'Failed to inject .DLL {self.injectors[pid].path.split("/")[-1]} into {item.text()}')
                else:
                    QMessageBox.information(self, "Info", f'Successful injected .DLL {self.injectors[pid].path.split("/")[-1]} into {item.text()}')
        else:
            try:
                self.injectors[pid].unload()
            except Exception as e:
                QMessageBox.critical(self, "Error", f'Failed to unload .DLL {self.injectors[pid].path.split("/")[-1]} into {item.text()}')
            else:
                QMessageBox.information(self, "Info", f'Successful unloaded .DLL {self.injectors[pid].path.split("/")[-1]} into {item.text()}')
        