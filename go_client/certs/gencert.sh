openssl genpkey -algorithm Ed25519 -out client.key
openssl req -new -key client.key -out client.csr -subj '/CN=client-192.168.1.5'

# client certificate by signing with server's certificate
echo "00" > file.srl
openssl x509 -req -in client.csr -CA server.crt -CAkey server.key -CAserial file.srl -out client.crt

echo "Client cert and key created"
echo "==========================="
openssl x509 -noout -text -in client.crt
echo "==========================="
