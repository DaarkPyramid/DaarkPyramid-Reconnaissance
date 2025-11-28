def run(url, headers, body):
    indicators = ["wp-content", "wp-includes", "wp-json", "wordpress"]
    
    b = body.lower()
    for i in indicators:
        if i in b:
            return "WordPress detected"
    return None
