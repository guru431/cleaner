import base64
import json

import httpx
import pytest

from cleaner.local_llm import LocalLLM, LocalLLMConfig, LocalLLMError, check_address

CONFIG = LocalLLMConfig("http://127.0.0.1:30000/v1", "qwen-27b-fast", "k-test-secret")


def client(handler, sleeps=None) -> LocalLLM:
    return LocalLLM(CONFIG, httpx.MockTransport(handler), sleep=(sleeps.append if sleeps is not None else lambda s: None))


def chat_answer(content, finish="stop"):
    return httpx.Response(200, json={"choices": [{"message": {"content": content}, "finish_reason": finish}]})


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:30000/v1", "http://localhost:30000/v1", "http://example:30000/v1",
    "https://192.168.41.41:30010/v1", "http://[::1]:30000/v1", "https://llm.corp.example/v1",
])
def test_loopback_private_and_trusted_addresses_are_accepted(url):
    check_address(url, frozenset({"llm.corp.example"}))


@pytest.mark.parametrize("url", [
    "https://api.example.com/v1", "http://8.8.8.8:30000/v1", "ftp://127.0.0.1/v1", "127.0.0.1:30000",
])
def test_public_unknown_or_malformed_addresses_are_refused(url):
    """SEC-12: облачный сервис нельзя по ошибке указать вместо локальной модели."""
    with pytest.raises(ValueError):
        check_address(url, frozenset())


def test_completion_sends_the_model_the_schema_and_the_bearer_key():
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers["Authorization"], json.loads(request.content)))
        return chat_answer('{"items": []}')

    assert client(handler).complete([{"role": "user", "content": "x"}], max_tokens=64, json_schema={"type": "object"}) == '{"items": []}'
    path, auth, body = seen[0]
    assert (path, auth) == ("/v1/chat/completions", "Bearer k-test-secret")
    assert (body["model"], body["temperature"], body["max_tokens"]) == ("qwen-27b-fast", 0, 64)
    assert body["response_format"]["json_schema"]["schema"] == {"type": "object"}
    assert "k-test-secret" not in repr(CONFIG)


@pytest.mark.parametrize(("response", "code"), [
    (chat_answer("обрезано", "length"), "length"),
    (chat_answer(None), "empty"),
    (httpx.Response(401, json={"error": "bad key"}), "auth"),
    (httpx.Response(500, text="oops"), "http"),
    (httpx.Response(200, text="не JSON"), "bad_response"),
])
def test_completion_failures_have_codes(response, code):
    with pytest.raises(LocalLLMError) as raised:
        client(lambda request: response).complete([{"role": "user", "content": "x"}], max_tokens=8)
    assert raised.value.code == code


def test_answer_to_a_question_may_be_cut_by_length():
    """FR-9.4: обрезанный ответ на вопрос пользователя полезнее отказа; слою 5 он по-прежнему не годится."""
    cut = client(lambda request: chat_answer("начало ответа", "length"))
    assert cut.answer([{"role": "user", "content": "x"}], max_tokens=8) == ("начало ответа", True)
    whole = client(lambda request: chat_answer("весь ответ"))
    assert whole.answer([{"role": "user", "content": "x"}], max_tokens=8) == ("весь ответ", False)


def test_unreachable_gateway_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(LocalLLMError) as raised:
        client(handler).complete([{"role": "user", "content": "x"}], max_tokens=8)
    assert raised.value.code == "unavailable"


def test_page_goes_to_the_gateway_root_and_a_busy_queue_is_waited_for():
    seen, sleeps = [], []
    answers = [
        httpx.Response(503, headers={"Retry-After": "7"}, json={"code": "overloaded"}),
        httpx.Response(200, json={"markdown": "# Страница", "chars": 9}),
    ]

    def handler(request):
        seen.append((request.url.path, json.loads(request.content)))
        return answers.pop(0)

    assert client(handler, sleeps).ocr_page(b"\x89PNG\r\n\x1a\nimage", "image/png") == "# Страница"
    assert [path for path, _ in seen] == ["/pages/ocr", "/pages/ocr"] and sleeps == [7.0]
    assert seen[0][1] == {"model": "ocr-ru", "image": base64.b64encode(b"\x89PNG\r\n\x1a\nimage").decode("ascii")}


@pytest.mark.parametrize(("status", "code"), [(413, "ocr_too_large"), (422, "ocr_empty"), (400, "ocr_bad_image")])
def test_page_refusals_have_codes(status, code):
    with pytest.raises(LocalLLMError) as raised:
        client(lambda request: httpx.Response(status, json={"code": "x"})).ocr_page(b"\xff\xd8\xff", "image/jpeg")
    assert raised.value.code == code


def test_unsupported_page_format_is_refused_without_a_request():
    def handler(request):
        raise AssertionError("запроса быть не должно")

    with pytest.raises(LocalLLMError) as raised:
        client(handler).ocr_page(b"GIF89a", "image/gif")
    assert raised.value.code == "ocr_format"
