from http.server import HTTPServer
from server.http_handler import HTTPHandler

def main():
    server = HTTPServer(("0.0.0.0", 8787), HTTPHandler)
    print("MCP server listening on http://127.0.0.1:8787")
    server.serve_forever()

if __name__ == "__main__":
    main()
