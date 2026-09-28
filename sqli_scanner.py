import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

BANNER = """
========================================
       SQL INJECTION SCANNER
========================================
"""


def build_url(url, parameter, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if parameter not in params:
        return None

    params[parameter] = [value]

    new_query = urlencode(params, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def get_parameters(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return list(params.keys())


def request_page(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )
        return response
    except requests.RequestException as error:
        print(f"[!] Request error: {error}")
        return None


def scan_parameter(url, parameter):
    print(f"\n[*] Testing parameter: {parameter}")

    normal_url = build_url(url, parameter, "1")

    if not normal_url:
        print("[!] Could not build test URL.")
        return

    normal_response = request_page(normal_url)

    if not normal_response:
        return

    normal_length = len(normal_response.text)

    print(f"[+] Normal response: {normal_response.status_code}")
    print(f"[+] Normal response size: {normal_length} bytes")

    payloads = [
        "1 OR 1=1",
        "1 AND 1=2"
    ]

    results = []

    for payload in payloads:
        test_url = build_url(url, parameter, payload)

        if not test_url:
            continue

        response = request_page(test_url)

        if not response:
            continue

        response_length = len(response.text)

        results.append({
            "payload": payload,
            "status": response.status_code,
            "length": response_length,
            "body": response.text
        })

        print(f"\n[*] Payload: {payload}")
        print(f"    Status: {response.status_code}")
        print(f"    Response size: {response_length} bytes")

    if len(results) != 2:
        print("\n[!] Could not complete all tests.")
        return

    true_test = results[0]
    false_test = results[1]

    true_body = true_test["body"]
    false_body = false_test["body"]

    true_length = true_test["length"]
    false_length = false_test["length"]

    if (
        true_test["status"] == 200
        and false_test["status"] == 200
        and true_length != false_length
    ):
        print("\n[!] POSSIBLE SQL INJECTION")
        print("[+] The true and false SQL conditions produced different responses.")

    elif (
        true_test["status"] == 200
        and false_test["status"] == 200
        and true_body != false_body
    ):
        print("\n[!] POSSIBLE SQL INJECTION")
        print("[+] The application responded differently to true and false conditions.")

    else:
        print("\n[-] No obvious SQL injection detected.")


def main():
    print(BANNER)

    target = input(
        "Enter a URL to test "
        "(example: http://127.0.0.1:5000/item?id=1): "
    ).strip()

    if not target:
        print("[!] No URL provided.")
        return

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        print("[!] URL must start with http:// or https://")
        return

    if not parsed.query:
        print("[!] The URL must contain a query parameter.")
        print("[!] Example: http://127.0.0.1:5000/item?id=1")
        return

    parameters = get_parameters(target)

    if not parameters:
        print("[!] No parameters found.")
        return

    print(f"\n[+] Parameters found: {', '.join(parameters)}")

    for parameter in parameters:
        scan_parameter(target, parameter)


if __name__ == "__main__":
    main()
