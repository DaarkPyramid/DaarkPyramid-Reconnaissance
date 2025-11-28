def run(url, headers, body):
    server = headers.get("Server", "").lower()
    if "nginx" in server:
        return f"Nginx detected ({server})"
    return None
