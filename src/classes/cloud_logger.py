# For Google CLoud Logging API (Third-party libraries)
from google.cloud import logging as gcp_logging
from google.cloud.logging.handlers import CloudLoggingHandler

# import Python's standard libraries
import pathlib
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
        self.__LOGGING_NAME = "cultured-downloader-api"
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

    def log(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "DEFAULT"

        The log entry will have no assigned severity level on GCP Cloud Logging.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="DEFAULT")

    def debug(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "DEBUG"
        used for debug or trace information.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="DEBUG")

    def info(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "INFO"
        used for routine information, such as ongoing status or performance.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="INFO")

    def notice(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "NOTICE"
        used for normal but significant events, such as start up, shut down, or a configuration change.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="NOTICE")

    def warning(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "WARNING"
        used for warning events that might cause problems.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="WARNING")

    def error(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "ERROR"
        used for error events that are likely to cause problems.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="ERROR")

    def critical(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "CRITICAL"
        used for critical events that cause more severe problems or outages.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="CRITICAL")

    def alert(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "ALERT"
        used when a person must take an action immediately.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="ALERT")

    def emergency(self, content: str | dict, log_name: str | None = None) -> None:
        """Logs a content with the given log name in GCP Cloud Logging with the severity of "EMERGENCY"
        used for emergency events that indicate one or more systems are unusable.

        Args:
            content (str|dict): 
                The content to log
            log_name (str, optional):
                The name of the log with the given content

        Returns:
            None
        """
        self.__write_log_entry(log_name=log_name, log_message=content, severity="EMERGENCY")

    def __write_log_entry(self, log_name: str | None = None, 
                        log_message: str | dict = None, severity: str | None = None) -> None:
        """Writes an entry to the given log location.

        Args:
            log_name (str): The location of the log to write to
                Defaults to "cultured-downloader-api"
            log_message (str|dict): The message to write to the log
                The message is written to the log with the given severity
                More details on how to write the log messages:
                    https://cloud.google.com/logging/docs/samples/logging-write-log-entry
            severity (str, optional): The severity of the log entry
                If severity is defined in the dict type log_message, you can leave the severity argument out
                If the log_message is a str, the severity argument is required
                If severity is not defined, it will be set to "DEFAULT" severity
                More details on the severity type:
                    https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity

        Returns:
            None

        Raises:
            - ValueError:
                - If the log_name is not defined
                - If the log_message is not defined
                - If the severity is not valid
            - TypeError:
                - If the severity is not a str
                - If the log_message is not a str or dict type
        """
        if (log_message is None):
            raise ValueError("log_message must be defined!")

        if (log_name is None):
            log_name = self.__LOGGING_NAME

        if (severity is None):
            severity = "DEFAULT"
        elif (isinstance(severity, str)):
            severity = severity.upper()
            if (severity not in self.__LOGGING_SEVERITY_TUPLE):
                raise ValueError(f"{severity} severity is not valid!")
        else:
            raise TypeError("severity must be a str or a valid severity!")

        stack_level = 0
        stack_traceback = []

        try:
            while (1):
                data = getframeinfo(stack()[stack_level][0])
                if (C.ROOT_DIR_PATH not in pathlib.Path(data.filename).parents):
                    break

                stack_traceback.append({
                    "stack_level": stack_level,
                    "filename": pathlib.Path(data.filename).name,
                    "line_no": data.lineno,
                    "function": f"{data.function}()" if (data.function != "<module>") else data.function,
                    "code_context": [line.strip() for line in data.code_context],
                    "index": data.index
                })
                stack_level += 1
        except (IndexError):
            stack_traceback.append("No stack trace available!")

        logger = self.__LOGGING_CLIENT.logger(log_name)
        if (isinstance(log_message, dict)):
            if ("severity" not in log_message):
                log_message["severity"] = severity
            log_message["stack_traceback"] = stack_traceback
            logger.log_struct(log_message)
        elif (isinstance(log_message, str)):
            log_message = {"message": log_message, "severity": severity, "stack_traceback": stack_traceback}
            logger.log_struct(log_message)
        else:
            raise TypeError("log message must be a str or dict")

CLOUD_LOGGER = CloudLogger()

__all__ = [
    "CLOUD_LOGGER"
]