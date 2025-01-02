# -*- coding: utf-8 -*-

"""Main module."""
from logging import Logger, DEBUG, INFO, CRITICAL, ERROR, WARNING, raiseExceptions, FileHandler

from logstash import TCPLogstashHandler


class LogstashLogger(Logger):
    def __init__(self, logger_name,
                 file_name=None,
                 host="localhost",
                 port=5000,
                 extra=None,
                 **kwargs):
        """

        :param logger_name:
        :param file_name:
        :param host:
        :param port:
        :param extra:
        :param kwargs:
        """

        super().__init__(name=logger_name)
        if file_name is not None:
            self.addHandler(FileHandler(filename=file_name))
        self.addHandler(TCPLogstashHandler(host, port, version=1))
        self.extra = extra

    def debug(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)
        """
        kwargs["extra"] = {**self.extra, **kwargs.get("extra")}
        if self.isEnabledFor(DEBUG):
            self._log(DEBUG, msg, args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'INFO'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.info("Houston, we have a %s", "interesting problem", exc_info=1)
        """
        if kwargs.get("extra") is not None:
            kwargs["extra"] = {**self.extra, **kwargs["extra"]}
        elif self.extra is not None:
            kwargs["extra"] = self.extra

        if self.isEnabledFor(INFO):
            self._log(INFO, msg, args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'WARNING'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.warning("Houston, we have a %s", "bit of a problem", exc_info=1)
        """
        if kwargs.get("extra") is not None:
            kwargs["extra"] = {**self.extra, **kwargs["extra"]}
        elif self.extra is not None:
            kwargs["extra"] = self.extra

        if self.isEnabledFor(WARNING):
            self._log(WARNING, msg, args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'ERROR'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.error("Houston, we have a %s", "major problem", exc_info=1)
        """
        if kwargs.get("extra") is not None:
            kwargs["extra"] = {**self.extra, **kwargs["extra"]}
        elif self.extra is not None:
            kwargs["extra"] = self.extra

        if self.isEnabledFor(ERROR):
            self._log(ERROR, msg, args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'CRITICAL'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.critical("Houston, we have a %s", "major disaster", exc_info=1)
        """
        if kwargs.get("extra") is not None:
            kwargs["extra"] = {**self.extra, **kwargs["extra"]}
        elif self.extra is not None:
            kwargs["extra"] = self.extra

        if self.isEnabledFor(CRITICAL):
            self._log(CRITICAL, msg, args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        """
        Log 'msg % args' with the integer severity 'level'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.log(level, "We have a %s", "mysterious problem", exc_info=1)
        """
        if kwargs.get("extra") is not None:
            kwargs["extra"] = {**self.extra, **kwargs["extra"]}
        elif self.extra is not None:
            kwargs["extra"] = self.extra

        if not isinstance(level, int):
            if raiseExceptions:
                raise TypeError("level must be an integer")
            else:
                return
        if self.isEnabledFor(level):
            self._log(level, msg, args, **kwargs)
