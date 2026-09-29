import pytest

from listener import _SyslogTCPFramer, _TCPFramingError


def test_newline_framer_emits_multiple_messages_and_final_unterminated_message():
    framer = _SyslogTCPFramer(max_frame_bytes=1024)
    assert framer.feed(b"<13>one\n<13>two\n") == [b"<13>one", b"<13>two"]
    assert framer.feed(b"CEF:0|A|B|1|1|final|3|") == []
    assert framer.feed(eof=True) == [b"CEF:0|A|B|1|1|final|3|"]


def test_rfc6587_octet_counted_framer_handles_fragmentation_and_multiple_frames():
    first = b"CEF:0|A|FW|1|1|first|3|src=10.0.0.1"
    second = b"<13>Sep 24 09:00:00 host app: second"
    wire = str(len(first)).encode() + b" " + first + str(len(second)).encode() + b" " + second

    framer = _SyslogTCPFramer(max_frame_bytes=1024)
    cut = 7
    assert framer.feed(wire[:cut]) == []
    assert framer.feed(wire[cut:len(wire) - 5]) == [first]
    assert framer.feed(wire[-5:]) == [second]
    assert framer.feed(eof=True) == []


def test_octet_counted_truncated_frame_fails_closed_at_eof():
    framer = _SyslogTCPFramer(max_frame_bytes=1024)
    assert framer.feed(b"20 short") == []
    with pytest.raises(_TCPFramingError, match="truncated"):
        framer.feed(eof=True)


def test_octet_counted_declared_oversize_is_rejected_before_buffer_growth():
    framer = _SyslogTCPFramer(max_frame_bytes=32)
    with pytest.raises(_TCPFramingError, match="exceeds maximum size"):
        framer.feed(b"999 ")


def test_newline_unterminated_oversize_is_rejected():
    framer = _SyslogTCPFramer(max_frame_bytes=32)
    with pytest.raises(_TCPFramingError, match="exceeds maximum size"):
        framer.feed(b"x" * 33)
