from gui import *
from sys import argv
from PyQt6.QtWidgets import QApplication
app = QApplication(argv)
window = injectorMW()
window.show()
app.exec()
