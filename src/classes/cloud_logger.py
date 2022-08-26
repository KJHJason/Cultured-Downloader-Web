# For Google CLoud Logging API (Third-party libraries)
from google.cloud import logging as gcp_logging
from google.cloud.logging.handlers import CloudLoggingHandler

# import Python's standard libraries
import pathlib
from typing import Optional
from inspect import stack, getframeinfo

# import local python libraries
if (__package__ is None or __package__ == ""):
    from initialise import CONSTANTS as C
else:
    from .initialise import CONSTANTS as C

class CloudLogger:
    def __init__(self) -> None:
        self.__LOGGING_CLIENT = gcp_logging.Client.from_service_account_json(
            json_credentials_path=C.CONFIG_DIR_PATH.joinpath("google-logging.json")
        )
        self.__LOGGING_NAME = "cultured-downloader-web-app"
        self.__GOOGLE_LOGGING_HANDLER = CloudLoggingHandler(self.__LOGGING_CLIENT, name=self.__LOGGING_NAME)
        self.__LOGGING_SEVERITY_TUPLE = ("DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING",
                                        "ERROR", "CRITICAL", "ALERT", "EMERGENCY")

    @property
    def LOGGING_CLIENT(self) -> gcp_logging.Client:
        return self.__LOGGING_CLIENT
    @property
    def LOGGING_NAME(self) -> str:
        return self.__LOGGING_NAME
    @property
    def GOOGLE_LOGGING_HANDLER(self) -> CloudLoggingHandler:
        return self.__GOOGLE_LOGGING_HANDLER

    def write_log_entry(self, logName: Optional[str] = None, 
                        logMessage: str | dict = None, severity: Optional[str] = None) -> None:
        """Writes an entry to the given log location.

        Args:
            logName (str): The location of the log to write to
                Defaults to "cultured-downloader-web-app"
            logMessage (str|dict): The message to write to the log
                The message is written to the log with the given severity
                More details on how to write the log messages:
                    https://cloud.google.com/logging/docs/samples/logging-write-log-entry
            severity (str, optional): The severity of the log entry
                If severity is defined in the dict type logMessage, you can leave the severity argument out
                If the logMessage is a str, the severity argument is required
                If severity is not defined, it will be set to "DEFAULT" severity
                More details on the severity type:
                    https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity

        Returns:
            None

        Raises:
            ValueError:
                If the logName is not defined
                If the logMessage is not defined
                If the severity is not valid
            TypeError:
                If the severity is not a str
                If the logMessage is not a str or dict type
        """
        if (logMessage is None):
            raise ValueError("logMessage must be defined!")

        if (logName is None):
            logName = self.__LOGGING_NAME

        if (severity is None):
            severity = "DEFAULT"
        elif (isinstance(severity, str)):
            severity = severity.upper()
            if (severity not in self.__LOGGING_SEVERITY_TUPLE):
                raise ValueError(f"{severity} severity is not valid!")
        else:
            raise TypeError("severity must be a str or a valid severity!")

        stackLevel = 0
        stackTraceback = []

        try:
            while (1):
                data = getframeinfo(stack()[stackLevel][0])
                if (C.ROOT_DIR_PATH not in pathlib.Path(data.filename).parents):
                    break

                stackTraceback.append({
                    "stackLevel": stackLevel,
                    "filename": pathlib.Path(data.filename).name,
                    "lineNo": data.lineno,
                    "function": f"{data.function}()" if (data.function != "<module>") else data.function,
                    "codeContext": [line.strip() for line in data.code_context],
                    "index": data.index
                })
                stackLevel += 1
        except (IndexError):
            stackTraceback.append("No stack trace available!")

        logger = self.__LOGGING_CLIENT.logger(logName)
        if (isinstance(logMessage, dict)):
            if ("severity" not in logMessage):
                logMessage["severity"] = severity
            logMessage["stack_traceback"] = stackTraceback
            logger.log_struct(logMessage)
        elif (isinstance(logMessage, str)):
            logMessage = {"message": logMessage, "severity": severity, "stack_traceback": stackTraceback}
            logger.log_struct(logMessage)
        else:
            raise TypeError("logMessage must be a str or dict")

CLOUD_LOGGER = CloudLogger()

__all__ = [
    "CLOUD_LOGGER"
]