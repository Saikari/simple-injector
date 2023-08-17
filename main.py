from sys import argv
from PyQt6.QtWidgets import QApplication
from injectorMW import injectorMW

app = QApplication(argv)
window = injectorMW()
window.show()
app.exec()
