import pytest

import httplib2
from httplib2.decode import LimitDecoder, ZlibDecoder, DecodeLimitError, DecodeRatioError
import tests


def test_gzip_head():
    # Test that we don't try to decompress a HEAD response
    http = httplib2.Http()
    response = tests.http_response_bytes(
        headers={"content-encoding": "gzip", "content-length": 42}
    )
    with tests.server_const_bytes(response) as uri:
        response, content = http.request(uri, "HEAD")
        assert response.status == 200
        assert int(response["content-length"]) != 0
        assert content == b""


def test_gzip_get():
    # Test that we support gzip compression
    http = httplib2.Http()
    response = tests.http_response_bytes(
        headers={"content-encoding": "gzip"},
        body=tests.gzip_compress(b"properly compressed"),
    )
    with tests.server_const_bytes(response) as uri:
        response, content = http.request(uri, "GET")
        assert response.status == 200
        assert "content-encoding" not in response
        assert "-content-encoding" in response
        assert int(response["content-length"]) == len(b"properly compressed")
        assert content == b"properly compressed"


def test_gzip_post_response():
    http = httplib2.Http()
    response = tests.http_response_bytes(
        headers={"content-encoding": "gzip"},
        body=tests.gzip_compress(b"properly compressed"),
    )
    with tests.server_const_bytes(response) as uri:
        response, content = http.request(uri, "POST", body=b"")
        assert response.status == 200
        assert "content-encoding" not in response
        assert "-content-encoding" in response


def test_gzip_malformed_response():
    http = httplib2.Http()
    # Test that we raise a good exception when the gzip fails
    http.force_exception_to_status_code = False
    response = tests.http_response_bytes(
        headers={"content-encoding": "gzip"}, body=b"obviously not compressed"
    )
    with tests.server_const_bytes(response, request_count=2) as uri:
        with tests.assert_raises(httplib2.FailedToDecompressContent):
            http.request(uri, "GET")

        # Re-run the test with out the exceptions
        http.force_exception_to_status_code = True

        response, content = http.request(uri, "GET")
        assert response.status == 500
        assert response.reason.startswith("Content purported")


def test_deflate_get():
    # Test that we support deflate compression
    http = httplib2.Http()
    response = tests.http_response_bytes(
        headers={"content-encoding": "deflate"},
        body=tests.deflate_compress(b"properly compressed"),
    )
    with tests.server_const_bytes(response) as uri:
        response, content = http.request(uri, "GET")
        assert response.status == 200
        assert "content-encoding" not in response
        assert int(response["content-length"]) == len(b"properly compressed")
        assert content == b"properly compressed"


def test_deflate_malformed_response():
    # Test that we raise a good exception when the deflate fails
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    response = tests.http_response_bytes(
        headers={"content-encoding": "deflate"}, body=b"obviously not compressed"
    )
    with tests.server_const_bytes(response, request_count=2) as uri:
        with tests.assert_raises(httplib2.FailedToDecompressContent):
            http.request(uri, "GET")

        # Re-run the test with out the exceptions
        http.force_exception_to_status_code = True

        response, content = http.request(uri, "GET")
        assert response.status == 500
        assert response.reason.startswith("Content purported")


def test_zlib_get():
    # Test that we support zlib compression
    http = httplib2.Http()
    response = tests.http_response_bytes(
        headers={"content-encoding": "deflate"},
        body=tests.zlib_compress(b"properly compressed"),
    )
    with tests.server_const_bytes(response) as uri:
        response, content = http.request(uri, "GET")
        assert response.status == 200
        assert "content-encoding" not in response
        assert int(response["content-length"]) == len(b"properly compressed")
        assert content == b"properly compressed"


# CVE-2026-59939: decompression is limited by output size and ratio.
# Tests backported from upstream 87581ad6 (httplib2 0.32.0).


def test_gzip_excess_ratio():
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    original = b"\x00" * (50 << 20)  # 50 MiB to ~50 KiB
    response = tests.http_response_bytes(
        headers={"content-encoding": "gzip"},
        body=tests.gzip_compress(original),
    )
    with tests.server_const_bytes(response) as uri:
        with pytest.raises(DecodeRatioError):
            http.request(uri, "GET")


def test_deflate_excess_ratio():
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    original = b"\x00" * (50 << 20)
    response = tests.http_response_bytes(
        headers={"content-encoding": "deflate"},
        body=tests.deflate_compress(original),
    )
    with tests.server_const_bytes(response) as uri:
        with pytest.raises(DecodeRatioError):
            http.request(uri, "GET")


def test_gzip_hard_limit_from_argument():
    http = httplib2.Http(decode_limit_hard=1000, decode_limit_safe=0, decode_limit_ratio=0)
    http.force_exception_to_status_code = False
    response = tests.http_response_bytes(
        headers={"content-encoding": "gzip"},
        body=tests.gzip_compress(tests.randbytes(2000)),
    )
    with tests.server_const_bytes(response) as uri:
        with pytest.raises(DecodeLimitError):
            http.request(uri, "GET")


def test_decode_limit_from_environment(monkeypatch):
    monkeypatch.setenv("HTTPLIB2_DECODE_LIMIT_HARD", "1234")
    monkeypatch.setenv("httplib2_decode_limit_ratio", "7.5")
    http = httplib2.Http(decode_limit_ratio=3)
    assert http.limit_kwargs == {"hard_limit": 1234, "ratio": 3.0}


@pytest.mark.parametrize("safe_limit", (0, 1000, 20000))
def test_limitdecoder_normal_decompression_no_limits(safe_limit):
    """Standard decompression of random data should pass with any safe_limit"""
    original = tests.randbytes(10 << 10)
    compressed = tests.zlib_compress(original)

    decoder = LimitDecoder(ZlibDecoder(), ratio=10, safe_limit=safe_limit, hard_limit=len(original) + 1)
    result = decoder.consume_bytes(compressed)
    assert result == original
    assert decoder._output_length == len(original)


def test_limitdecoder_normal_rechunking():
    """Passing a massive single chunk should be re-chunked internally without error"""
    original = b"\x00" * (10 << 20)
    compressed = tests.zlib_compress(original)
    assert len(compressed) > 2000

    decoder = LimitDecoder(ZlibDecoder(), ratio=2000, chunk_size=512, safe_limit=0, hard_limit=len(original) + 1)
    result = decoder.consume_bytes(compressed, chunk_size=0)
    assert result == original
    assert decoder._consumed_length == len(compressed)


def test_limitdecoder_amplification_ratio_exceeded():
    """High ratio should trigger DecodeRatioError above safe_limit"""
    original = b"\x00" * (1 << 20)
    compressed = tests.zlib_compress(original)

    decoder = LimitDecoder(ZlibDecoder(), ratio=10, chunk_size=512, safe_limit=0, hard_limit=len(original) + 1)
    with pytest.raises(DecodeRatioError):
        decoder.consume_bytes(compressed, chunk_size=0)
    assert decoder._consumed_length == 512, "expected ratio error on first chunk"


@pytest.mark.parametrize("ratio", (0, 10, 1000))
def test_limitdecoder_hard_limit_exceeded(ratio):
    """Output exceeding hard_limit must trigger DecodeLimitError regardless of ratio"""
    original = b"\x00" * (10 << 10)
    compressed = tests.zlib_compress(original)

    decoder = LimitDecoder(ZlibDecoder(), ratio=ratio, safe_limit=0, hard_limit=len(original) - 1)
    with pytest.raises(DecodeLimitError):
        decoder.consume_bytes(compressed)


@pytest.mark.parametrize("ratio", (0, 10, 1000))
def test_limitdecoder_safe_limit_bypass(ratio):
    """Any ratio allowed if total output < safe_limit"""
    original = b"\x00" * (10 << 10)
    compressed = tests.zlib_compress(original)

    decoder = LimitDecoder(ZlibDecoder(), ratio=ratio, safe_limit=len(original) + 1, hard_limit=len(original) + 1)
    result = decoder.consume_bytes(compressed)
    assert result == original
    assert decoder._output_length == len(original)


def test_limitdecoder_single_byte_feeding():
    """Feeding compressed data 1 byte at a time should still decode correctly"""
    original = tests.randbytes(10 << 10)
    compressed = tests.zlib_compress(original)

    decoder = LimitDecoder(ZlibDecoder(), ratio=10, safe_limit=5 << 10, hard_limit=len(original) + 1)
    result = decoder.consume_bytes(compressed, chunk_size=1)
    assert result == original


@pytest.mark.parametrize("name", ("ratio", "chunk_size", "safe_limit", "hard_limit"))
def test_limitdecoder_invalid_argument(name):
    with pytest.raises(ValueError) as e:
        LimitDecoder(ZlibDecoder(), **{name: -1})
    assert "expected >= 0" in str(e.value).lower()


@pytest.mark.parametrize("name", ("needs_input", "decode", "flush"))
def test_zlibdecoder_invalid_after_flush(name):
    checks = {
        "needs_input": lambda d: d.needs_input,
        "decode": lambda d: d.decode(b""),
        "flush": lambda d: d.flush(),
    }
    d = ZlibDecoder()
    d.decode(tests.zlib_compress(b""))
    d.flush()
    with pytest.raises(RuntimeError) as e:
        checks[name](d)
    assert "used after flush" in str(e.value).lower()


def test_deflate_zlib_wrapped_excess_ratio():
    # 0.21.0 accepts zlib-wrapped deflate; that path is limited too.
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    original = b"\x00" * (50 << 20)
    response = tests.http_response_bytes(
        headers={"content-encoding": "deflate"},
        body=tests.zlib_compress(original),
    )
    with tests.server_const_bytes(response) as uri:
        with pytest.raises(DecodeRatioError):
            http.request(uri, "GET")
