from ctypes import create_unicode_buffer, windll
from win32gui import EnumWindows, GetClassLong, GetIconInfo
import PySide6.QtGui
import PySide6.QtCore
import PySide6.QtWidgets
from psutil import process_iter, STATUS_RUNNING, Process
from win32gui import FindWindow, GetWindowText, GetClassName, GetForegroundWindow, ExtractIcon
from Bypass import Bypass
from win32process import GetWindowThreadProcessId
from re import search
import win32api

regex = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
import psutil
import win32process
import win32gui
import ctypes


def enum_windows_callback(hwnd, window_list):
    window_text = GetWindowText(hwnd)
    class_name = GetClassName(hwnd)
    _, pid = GetWindowThreadProcessId(hwnd)
    process = Process(pid)
    window_list.append((process.name(), hwnd, class_name, pid, window_text, process.exe()))


def get_all_windows():
    window_list = []
    EnumWindows(enum_windows_callback, window_list)
    return window_list


def get_file_icon(file_path):
    return PySide6.QtWidgets.QFileIconProvider().icon(PySide6.QtCore.QFileInfo(file_path))


class injectorMW(PySide6.QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process List")
        self.injectors = {}
        self.processLW = PySide6.QtWidgets.QTableWidget(self)
        self.processLW.cellClicked.connect(self.selectRow)
        # self.processLW.itemClicked.connect(self.selectRow)
        self.processLW.setColumnCount(4)
        self.processLW.setHorizontalHeaderLabels(["Process Name", "Window Class Name", "PID"])
        self.processlist = list(set([(p[0], p[2].strip(), p[3], p[-1]) for p in get_all_windows()
                                     if p[2] is not None
                                     and p[2] not in ("IME", "MSCTFIME UI")
                                     and not search(regex, p[2].strip())
                                     ]))
        self.processNames = [f'{i[0]}' for i in self.processlist]
        self.classNames = [f'{i[1]}' for i in self.processlist]
        self.pids = [f'{i[2]}' for i in self.processlist]
        self.pPaths = [f'{i[3]}' for i in self.processlist]
        self.processLW.setRowCount(len(self.processNames))
        # ProcessNameColumn = [QTableWidgetItem(self.processNames[i]) for i in range(len(self.processNames))]
        # WindowClassNameColumn = [QTableWidgetItem(self.classNames[i]) for i in range(len(self.classNames))]
        # PidsColumn = [QTableWidgetItem(self.pids[i]) for i in range(len(self.pids))]
        for i in range(len(self.processNames)):
            for i in range(len(self.processNames)):
                # Create a QTableWidgetItem for each row
                ProcessNameItem = PySide6.QtWidgets.QTableWidgetItem(self.processNames[i])
                WindowClassNameItem = PySide6.QtWidgets.QTableWidgetItem(self.classNames[i])
                PidsItem = PySide6.QtWidgets.QTableWidgetItem(self.pids[i])
                iconItem = PySide6.QtWidgets.QTableWidgetItem()
                icon = get_file_icon(self.pPaths[i])
                if icon:
                    iconItem.setIcon(icon)
                # Set the flags for the QTableWidgetItem

                ProcessNameItem.setFlags(ProcessNameItem.flags() & ~PySide6.QtGui.Qt.ItemIsEditable)
                WindowClassNameItem.setFlags(WindowClassNameItem.flags() & ~PySide6.QtGui.Qt.ItemIsEditable)
                PidsItem.setFlags(PidsItem.flags() & ~PySide6.QtGui.Qt.ItemIsEditable)
                # iconItem.setFlags(iconItem.flags() & ~Qt.ItemIsEditable)
                # Set the QTableWidgetItem in the corresponding cell
                self.processLW.setItem(i, 0, ProcessNameItem)
                self.processLW.setItem(i, 1, WindowClassNameItem)
                self.processLW.setItem(i, 2, PidsItem)
                self.processLW.setItem(i, 3, iconItem)
        #        for i, item in enumerate(QLWIs):
        #            item.setData(Qt.UserRole, (self.processlist[i][0], self.processlist[i][1]))
        self.processLW.itemDoubleClicked.connect(self.processItemDoubleClickHandler)
        self.processLW.setSortingEnabled(True)
        self.processLW.sortItems(0)

        self.processLW.horizontalHeader().setSectionResizeMode(PySide6.QtWidgets.QHeaderView.Stretch)
        #        self.processLW.sortItems()
        self.setCentralWidget(self.processLW)

    def selectRow(self, row, column):
        # Create a QTableWidgetSelectionRange object that represents the entire row

        row_range = PySide6.QtWidgets.QTableWidgetSelectionRange(row, 0, row, self.processLW.columnCount() - 1)
        # Select the entire row
        self.processLW.setRangeSelected(row_range, True)

    def processItemDoubleClickHandler(self, item):
        row_number = self.processLW.row(item)
        # Create a list to store the row items
        row_items = []
        # Iterate over the columns in the row
        for column in range(self.processLW.columnCount()):
            # Get the item in the row and column
            item = self.processLW.item(row_number, column)
            if item is not None:
                # Append the text of the item to the row_items list
                row_items.append(item.text())
        # Print the list of row items
        print(row_items)

        process_name = row_items[0]
        class_name = row_items[1]
        pid = row_items[2]
        if class_name not in self.injectors:
            fname, _ = PySide6.QtWidgets.QFileDialog.getOpenFileName(self,
                                                                     f'Select .DLL to inject into process {process_name}')
            if fname:
                try:
                    self.injectors[class_name] = Bypass()
                    # self.injectors[class_name].load_from_name(process_name)
                    self.injectors[class_name].Attack(fname, process_name, class_name, int(pid))
                except Exception as e:
                    PySide6.QtWidgets.QMessageBox.critical(self, "Error",
                                                           f'{e} Failed to inject .DLL '
                                                           f'{self.injectors[class_name].path.split("/")[-1] if self.injectors[class_name].path is not None else None} into {process_name}')
                else:
                    PySide6.QtWidgets.QMessageBox.information(self, "Info",
                                                              f'Successfully injected .DLL '
                                                              f'{self.injectors[class_name].path.split("/")[-1] if self.injectors[class_name].path is not None else None} into {process_name}')
        else:
            try:
                self.injectors[class_name].unload()
            except Exception as e:
                PySide6.QtWidgets.QMessageBox.critical(self, "Error",
                                                       f'{e} Failed to unload .DLL '
                                                       f'{self.injectors[class_name].path.split("/")[-1] if self.injectors[class_name].path is not None else None} from {process_name}')
            else:
                PySide6.QtWidgets.QMessageBox.information(self, "Info",
                                                          f'Successfully unloaded .DLL '
                                                          f'{self.injectors[class_name].path.split("/")[-1] if self.injectors[class_name].path is not None else None} from {process_name}')
