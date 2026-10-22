"""A full-screen live view of a run, in the spirit of top and ntop.

Each route gets a row that moves through its stages (queued, bootstrap
with Tor's own progress, connect, download, done) and fills in its
measurements as they arrive, while log lines scroll underneath. It uses
plain ANSI escapes on the alternate screen, so it needs no dependencies
and leaves the terminal as it found it.
"""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import os
import sys
import threading
import time
from typing import IO, Optional, Sequence

from torrelay import bench
from torrelay import report
from torrelay import tor
from torrelay import util

_ENTER = "\x1b[?1049h\x1b[?25l"  # Alternate screen, hide cursor.
_LEAVE = "\x1b[?25h\x1b[?1049l"
_HOME = "\x1b[H"
_CLEAR_LINE = "\x1b[K"
_CLEAR_BELOW = "\x1b[J"
_RESET = "\x1b[0m"

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_BAR_WIDTH = 10
_LOG_LINES = 500

# Display state -> (symbol, SGR colour).
_STYLES = {
    "queued": ("·", "2"),
    "bootstrap": ("◌", "36"),
    "testing": ("", "33"),
    "waiting": ("…", "34"),
    "done": ("✔", "32"),
    "failed": ("✘", "31"),
}
_HEADER_STYLE = "7"  # Reverse video, like top's column header.
_TITLE_STYLE = "1"

_COLUMNS = (  # (header, width, Result attribute, decimals)
    ("BOOT s", 7, "bootstrap_s", 1),
    ("CONN s", 7, "connect_s", 1),
    ("LAT ms", 7, "latency_ms", 0),
    ("DOWN KiB/s", 11, "down_kib", 0),
    ("UP KiB/s", 9, "up_kib", 0),
)
_RANK_WIDTH = 4
_NAME_WIDTH = 8
_STAGE_WIDTH = 22
_PROGRESS_WIDTH = _BAR_WIDTH + 6

Segment = tuple[str, str]  # (text, SGR colour or "")


@dataclasses.dataclass
class _Row:
    """What one route is doing right now.

    Attributes:
        stage: Latest stage reported, e.g. ``bootstrap: loading ...``.
        percent: Progress through the stage, when known.
        since: When the stage began, for the elapsed counter.
        result: Latest measurements.
    """

    stage: str = "queued"
    percent: Optional[int] = None
    since: float = dataclasses.field(default_factory=time.monotonic)
    result: Optional[bench.Result] = None


def _state(stage: str) -> str:
    """Groups a stage name into one of the display states.

    Args:
        stage: A stage from ``bench.Observer.stage``.

    Returns:
        A key of ``_STYLES``.
    """
    base = stage.split(":", 1)[0]
    if base in ("queued", "bootstrap", "done", "failed"):
        return base
    if base.startswith("waiting"):
        return "waiting"
    return "testing"


def _bar(percent: int) -> str:
    """Draws a progress bar with its percentage.

    Args:
        percent: 0 to 100.

    Returns:
        e.g. ``█████░░░░░  50%``.
    """
    filled = round(_BAR_WIDTH * percent / 100)
    return "█" * filled + "░" * (_BAR_WIDTH - filled) + f" {percent:>3}%"


def _fit(segments: Sequence[Segment], width: int, colour: bool) -> str:
    """Joins coloured segments, cutting the visible text at ``width``.

    Args:
        segments: ``(text, sgr)`` pairs.
        width: Terminal columns available.
        colour: Whether to emit colour escapes.

    Returns:
        One terminal line.
    """
    out, room = [], width
    for text, sgr in segments:
        if room <= 0:
            break
        piece = text[:room]
        room -= len(piece)
        out.append(f"\x1b[{sgr}m{piece}{_RESET}" if colour and sgr
                   else piece)
    return "".join(out)


def ranked(rows: Sequence[tuple[str, _Row]]) -> list[tuple[str, _Row]]:
    """Orders rows like the final table, so the view re-ranks live.

    Finished routes come first, best score first; routes still running
    keep their order below them; failed routes sink to the bottom.

    Args:
        rows: ``(name, row)`` pairs in display order.

    Returns:
        The same pairs, re-ordered.
    """
    def key(item: tuple[str, _Row]) -> tuple[int, float]:
        """Sorts by state group, then by score within finished routes."""
        _, row = item
        state = _state(row.stage)
        if state == "done" and row.result:
            return 0, -bench.score(row.result)
        return (2 if state == "failed" else 1), 0.0

    return sorted(rows, key=key)


def _clock(seconds: float) -> str:
    """Formats a duration as ``m:ss``.

    Args:
        seconds: Elapsed time.

    Returns:
        The duration.
    """
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}:{secs:02d}"


class Dashboard(bench.Observer):
    """Live, redrawing table of every route in a run.

    Use as a context manager around ``bench.run``/``bench.check``; it
    takes over the terminal and ``util.log`` until the run ends.
    """

    def __init__(self, title: str, stream: IO[str] = sys.stderr,
                 interval: float = 0.2) -> None:
        """Prepares the view without touching the terminal yet.

        Args:
            title: Shown on the first line, e.g. the command and target.
            stream: Terminal to draw on.
            interval: Seconds between redraws.
        """
        self._title = title
        self._stream = stream
        self._interval = interval
        self._colour = "NO_COLOR" not in os.environ
        self._lock = threading.Lock()
        self._rows: dict[str, _Row] = {}
        self._log: collections.deque[str] = collections.deque(
            maxlen=_LOG_LINES)
        self._started = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._exit = contextlib.ExitStack()

    # -- bench.Observer -----------------------------------------------------

    def begin(self, names: Sequence[str]) -> None:
        """Creates a row per route, in display order.

        Args:
            names: Route names.
        """
        with self._lock:
            for name in names:
                self._rows.setdefault(name, _Row())

    def stage(self, name: str, stage: str,
              percent: Optional[int] = None) -> None:
        """Moves a route to a new stage.

        Args:
            name: Route name.
            stage: What it is doing now.
            percent: Progress through the stage, when known.
        """
        with self._lock:
            row = self._rows.setdefault(name, _Row())
            if stage.split(":", 1)[0] != row.stage.split(":", 1)[0]:
                row.since = time.monotonic()
            row.stage, row.percent = stage, percent

    def update(self, result: bench.Result) -> None:
        """Records a route's latest measurements.

        Args:
            result: The route's result so far.
        """
        with self._lock:
            self._rows.setdefault(result.name, _Row()).result = result

    def add_log(self, message: str) -> None:
        """Keeps log lines for the scrolling pane under the table.

        Args:
            message: One ``util.log`` message, possibly multi-line.
        """
        lines = [line for line in message.splitlines() if line.strip()]
        with self._lock:
            self._log.extend(lines)

    # -- Terminal -----------------------------------------------------------

    def __enter__(self) -> Dashboard:
        """Switches to the alternate screen and starts redrawing.

        Returns:
            The dashboard, which is also the run's observer.
        """
        self._stream.write(_ENTER)
        self._exit.callback(self._restore)
        self._exit.enter_context(util.log_to(self.add_log))
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Stops redrawing and gives the terminal back.

        Args:
            *exc_info: Exception details, if the run raised.
        """
        self._stop.set()
        self._thread.join()
        self._exit.close()

    def _restore(self) -> None:
        """Leaves the alternate screen and shows the cursor again."""
        self._stream.write(_LEAVE)
        self._stream.flush()

    def _loop(self) -> None:
        """Redraws until stopped, then once more for the final state."""
        while not self._stop.wait(self._interval):
            self._draw()
        self._draw()

    def _size(self) -> os.terminal_size:
        """Reads the terminal size each frame, so resizes just work.

        Returns:
            Columns and lines, defaulting to 100x30 when unknown.
        """
        try:
            size = os.get_terminal_size(self._stream.fileno())
        except (OSError, ValueError):
            size = os.terminal_size((0, 0))
        return os.terminal_size((size.columns or 100, size.lines or 30))

    def _draw(self) -> None:
        """Writes one frame over the previous one."""
        size = self._size()
        lines = self.frame(size.columns, size.lines, time.monotonic())
        self._stream.write(_HOME + "".join(
            line + _CLEAR_LINE + "\n" for line in lines[:-1])
            + lines[-1] + _CLEAR_LINE + _CLEAR_BELOW)
        self._stream.flush()

    # -- Layout -------------------------------------------------------------

    def frame(self, width: int, height: int, now: float) -> list[str]:
        """Lays out a full screen: title, summary, table, then log.

        Args:
            width: Terminal columns.
            height: Terminal lines.
            now: Current ``time.monotonic()``, for timers and spinners.

        Returns:
            At most ``height`` lines.
        """
        with self._lock:
            rows = list(self._rows.items())
            log = list(self._log)
        elapsed = _clock(now - self._started)
        title = self._title[:max(width - len(elapsed) - 1, 0)]
        top = [
            _fit([(title.ljust(width - len(elapsed)), _TITLE_STYLE),
                  (elapsed, "")], width, self._colour),
            _fit(self._summary(rows), width, self._colour),
            "",
            _fit([(self._header().ljust(width), _HEADER_STYLE)], width,
                 self._colour),
            *(_fit(self._row(name, row, now, place), width, self._colour)
              for place, (name, row) in enumerate(ranked(rows), 1)),
            "",
        ]
        footer = _fit([("Ctrl-C to stop", "2")], width, self._colour)
        room = max(height - len(top) - 1, 0)
        tail = log[-room:] if room else []
        return [*top, *(line[:width] for line in tail), footer][:height]

    def _summary(self, rows: Sequence[tuple[str, _Row]]) -> list[Segment]:
        """Counts routes per state, e.g. ``2 bootstrap  1 testing``.

        Args:
            rows: Current rows.

        Returns:
            Segments for the summary line.
        """
        counts = collections.Counter(_state(row.stage) for _, row in rows)
        parts: list[Segment] = [(f"{len(rows)} routes", "")]
        for state, (_, sgr) in _STYLES.items():
            if counts[state]:
                parts.append((f"   {counts[state]} {state}", sgr))
        return parts

    @staticmethod
    def _header() -> str:
        """Renders the column titles.

        Returns:
            The header text.
        """
        cells = "".join(f"{title:>{width}}" for title, width, _, _
                        in _COLUMNS)
        return (f"{'#':>{_RANK_WIDTH - 1}} "
                f"{'ROUTE':<{_NAME_WIDTH}}{'STAGE':<{_STAGE_WIDTH}}"
                f"{'PROGRESS':<{_PROGRESS_WIDTH}}{cells}  PATH / STATUS")

    def _row(self, name: str, row: _Row, now: float,
             place: int) -> list[Segment]:
        """Renders one route's line.

        Args:
            name: Route name.
            row: Its live state.
            now: Current ``time.monotonic()``.
            place: Position in the ranking; shown once the route is done.

        Returns:
            Segments for the line.
        """
        state = _state(row.stage)
        symbol, sgr = _STYLES[state]
        if state == "testing":
            symbol = _SPINNER[int(now * 10) % len(_SPINNER)]
        base = row.stage.split(":", 1)[0]
        if state in ("bootstrap", "testing", "waiting"):
            base = f"{base} {now - row.since:.0f}s"
        stage = f"{symbol} {base}"[:_STAGE_WIDTH - 1]
        result = row.result or bench.Result(name)
        cells = "".join(report.number(getattr(result, attr), width, decimals)
                        for _, width, attr, decimals in _COLUMNS)
        rank = str(place) if state == "done" else ""
        return [
            (f"{rank:>{_RANK_WIDTH - 1}} ", sgr),
            (f"{name:<{_NAME_WIDTH}}", "1"),
            (f"{stage:<{_STAGE_WIDTH}}", sgr),
            (f"{self._progress(state, row):<{_PROGRESS_WIDTH}}", sgr),
            (cells + "  ", ""),
            self._status(state, row, result),
        ]

    @staticmethod
    def _progress(state: str, row: _Row) -> str:
        """Shows the bootstrap bar while Tor starts, full once finished.

        Args:
            state: Display state.
            row: The route's live state.

        Returns:
            The progress cell text.
        """
        if state == "bootstrap":
            return _bar(row.percent or 0)
        if state in ("testing", "waiting", "done"):
            return _bar(100)
        return ""

    @staticmethod
    def _status(state: str, row: _Row, result: bench.Result) -> Segment:
        """Picks the most useful trailing text for a route.

        Args:
            state: Display state.
            row: The route's live state.
            result: Its measurements so far.

        Returns:
            The error, Tor's bootstrap message, or the circuit path.
        """
        if result.error:
            return result.error, _STYLES["failed"][1]
        if state == "bootstrap" and ":" in row.stage:
            return row.stage.split(":", 1)[1].strip(), "2"
        detail = f"  [{result.detail}]" if result.detail else ""
        return tor.format_path(result.hops) + detail, ""


def wanted(stream: IO[str] = sys.stderr) -> bool:
    """Whether a live view can be drawn on ``stream``.

    Args:
        stream: Where it would be drawn.

    Returns:
        True for an interactive, capable terminal.
    """
    return stream.isatty() and os.environ.get("TERM", "dumb") != "dumb"
