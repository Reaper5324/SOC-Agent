import json
from urllib import error, request


def generate_incident_summary(host, model, prompt, timeout=60):
    base_url = host.rstrip("/")
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }
    data = json.dumps(payload).encode("utf-8")

    http_request = request.Request(
        f"{base_url}/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (error.URLError, TimeoutError, ConnectionError) as exc:
        raise RuntimeError(f"Unable to reach Ollama at {base_url}: {exc}") from exc

    try:
        payload = json.loads(body)
        response_text = payload["response"]
        return json.loads(response_text)
    except (KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError("Ollama returned an invalid response payload.") from exc
