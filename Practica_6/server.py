import http.server
import ssl

# Create an HTTP server instance in port 4443 (access it through https://localhost:4443 or https://127.0.0.1:4443)
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Wrap the socket with the latest TLS encryption (ssl.PROTOCOL_TLS_SERVER para 1.3 y ssl.PROTOCOL_TLSv1_2 para 1.2) and use the server certificate 'server.crt' and its private key 'key.pem'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('Juan_Carlos_Alcausa.crt', 'Juan_Carlos_Alcausa.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

# Start the HTTPS server and keep it foreves until finishing the process
httpd.serve_forever()