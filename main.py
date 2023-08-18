from sys import argv
from PySide6.QtWidgets import QApplication
from injectorMW import injectorMW
import PySide6
from logging import basicConfig, DEBUG, FileHandler, StreamHandler
# Configure logging
basicConfig(level=DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                FileHandler('debug.log'),
                StreamHandler()
            ]
            )

app = QApplication(argv)
window = injectorMW()
window.show()
app.exec()
