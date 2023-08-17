from sys import argv
from PyQt5.QtWidgets import QApplication
from injectorMW import injectorMW

app = QApplication(argv)
window = injectorMW()
window.show()
app.exec()
