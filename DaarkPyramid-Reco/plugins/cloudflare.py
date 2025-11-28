def run(url, headers, body):
    h = str(headers).lower()
    if "cloudflare" in h or "cf-ray" in h:
        return "CDN/WAF: Cloudflare detected"
    return None
