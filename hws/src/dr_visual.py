import time

PROGRESS_BAR_LENGTH = 40
PROGRESS_BAR_CHAR = "="


def interactive_progress_bar(index, total, title = ''):
    percent = int(100 * (index / total))
    completed = int(PROGRESS_BAR_LENGTH * (index / total))
    bar = PROGRESS_BAR_CHAR * completed + '-' * (PROGRESS_BAR_LENGTH - completed)
    _str = "\r%s |%s| %s%%" % (title, bar, str(percent))
    print(_str, end = "\r")
    if index == total:
        print()
