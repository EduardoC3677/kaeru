from __future__ import annotations

import logging
import sys

_INSTALLED = False


def install_console_logging(level: int = logging.INFO, *, use_rich: bool = True) -> None:
    global _INSTALLED
    if _INSTALLED:
        logging.getLogger().setLevel(level)
        return

    if use_rich:
        try:
            from rich.logging import RichHandler

            handler: logging.Handler = RichHandler(
                show_time=True,
                show_level=True,
                show_path=False,
                rich_tracebacks=True,
                markup=False,
            )
            fmt = "%(message)s"
        except ImportError:
            handler = logging.StreamHandler(sys.stderr)
            fmt = "%(asctime)s %(levelname)-7s %(name)s | %(message)s"
    else:
        handler = logging.StreamHandler(sys.stderr)
        fmt = "%(asctime)s %(levelname)-7s %(name)s | %(message)s"

    handler.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    _INSTALLED = True


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name or "kaeru_mtk")
