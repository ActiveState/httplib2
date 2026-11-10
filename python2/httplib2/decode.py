# -*- coding: utf-8 -*-
"""Bounded decompression of response bodies (CVE-2026-59939).

Backported from httplib2 0.32.0 (httplib2/decode.py, upstream 87581ad6) for
the Python 2.7 line: no type annotations, no f-strings, no typing.Protocol.
"""
import zlib


class DecodeRatioError(Exception):
    """Output-to-input amplification ratio exceeded the configured limit."""


class DecodeLimitError(Exception):
    """Total output length exceeded the hard limit."""


class DecoderProtocol(object):
    @property
    def needs_input(self):
        raise NotImplementedError

    def decode(self, b):
        raise NotImplementedError

    def flush(self):
        raise NotImplementedError

    def consume_bytes(self, data, chunk_size=64 << 10):
        out = bytearray()
        if chunk_size == 0:
            chunk_size = len(data)
        for i in range(0, len(data), max(chunk_size, 1)):
            chunk = data[i : i + chunk_size]
            out.extend(self.decode(chunk))
        out.extend(self.flush())
        return bytes(out)


class ZlibDecoder(DecoderProtocol):
    """Thin wrapper around zlib.decompressobj conforming to the decoder interface.

    zlib returns all available output for the input it is given, so it never
    holds output back; needs_input stays True until the stream ends. Python 2's
    decompress objects have no ``eof`` attribute, and there needs_input is
    always True, which gives the same behaviour.
    """

    __slots__ = ("_decoder",)

    WBITS_DEFLATE = -15
    WBITS_ZLIB = 15
    WBITS_GZIP = 15 | 16
    WBITS_AUTO_GZIP_ZLIB = 15 | 32  # but not deflate

    def __init__(self, wbits=WBITS_AUTO_GZIP_ZLIB):
        self._decoder = zlib.decompressobj(wbits)

    @property
    def needs_input(self):
        if self._decoder is None:
            raise RuntimeError("used after flush()")
        return not getattr(self._decoder, "eof", False)

    def decode(self, b):
        if self._decoder is None:
            raise RuntimeError("used after flush()")
        return self._decoder.decompress(b)

    def flush(self):
        if self._decoder is None:
            raise RuntimeError("used after flush()")
        result = self._decoder.flush()
        self._decoder = None
        return result


def GzipDecoder():
    return ZlibDecoder(ZlibDecoder.WBITS_GZIP)


def DeflateDecoder():
    return ZlibDecoder(ZlibDecoder.WBITS_DEFLATE)


class LimitDecoder(DecoderProtocol):
    __slots__ = (
        "_decoder",
        "_ratio",
        "_chunk_size",
        "_safe_limit",
        "_hard_limit",
        "_consumed_length",
        "_output_length",
        "_input_buffer",
        "_flushed",
    )

    def __init__(self, decoder, ratio=100, chunk_size=64 << 10, safe_limit=10 << 20, hard_limit=10 << 30):
        if ratio < 0:
            raise ValueError("LimitDecoder() ratio={0} expected >= 0".format(ratio))
        if chunk_size < 0:
            raise ValueError("LimitDecoder() chunk_size={0} expected >= 0".format(chunk_size))
        if safe_limit < 0:
            raise ValueError("LimitDecoder() safe_limit={0} expected >= 0".format(safe_limit))
        if hard_limit < 0:
            raise ValueError("LimitDecoder() hard_limit={0} expected >= 0".format(hard_limit))

        self._decoder = decoder
        self._ratio = ratio
        self._chunk_size = chunk_size or (64 << 10)
        self._safe_limit = safe_limit
        self._hard_limit = hard_limit
        self._consumed_length = 0
        self._output_length = 0
        self._input_buffer = bytearray()
        self._flushed = False

    def _check_limits(self):
        if (self._hard_limit > 0) and (self._output_length > self._hard_limit):
            raise DecodeLimitError(
                "Output length {0} exceeds hard limit {1}".format(self._output_length, self._hard_limit)
            )
        if (self._safe_limit > 0) and (self._output_length < self._safe_limit):
            return
        if (self._ratio > 0) and (self._output_length > self._consumed_length * self._ratio):
            if self._consumed_length > 0:
                actual_ratio = float(self._output_length) / self._consumed_length
            else:
                actual_ratio = float("inf")
            raise DecodeRatioError(
                "Amplification ratio {0:.1f} ({1}/{2}) exceeds limit {3}".format(
                    actual_ratio, self._output_length, self._consumed_length, self._ratio
                )
            )

    @property
    def needs_input(self):
        return self._decoder.needs_input

    def decode(self, b):
        if self._flushed:
            raise RuntimeError("decode() called after flush()")
        return bytes(self._pump(b))

    def flush(self):
        if self._flushed:
            raise RuntimeError("flush() called more than once")
        self._flushed = True

        output = self._pump(b"")

        data = self._decoder.flush()
        output.extend(data)
        self._output_length += len(data)
        self._check_limits()

        return bytes(output)

    def _pump(self, b):
        self._input_buffer.extend(b)

        output = bytearray()
        while True:
            if not self._decoder.needs_input:
                data = self._decoder.decode(b"")
                if data:
                    output.extend(data)
                    self._output_length += len(data)
                    self._check_limits()
                    continue

            if self._input_buffer:
                chunk = bytes(self._input_buffer[: self._chunk_size])
                del self._input_buffer[: self._chunk_size]

                data = self._decoder.decode(chunk)
                self._consumed_length += len(chunk)

                if data:
                    output.extend(data)
                    self._output_length += len(data)
                    self._check_limits()

                continue

            # neither input nor decoder progress
            break

        return output
