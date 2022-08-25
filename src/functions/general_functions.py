# import python standard libraries
import time

def format_server_time() -> str:
    serverTime = time.localtime()
    return time.strftime("%I:%M:%S %p", serverTime)