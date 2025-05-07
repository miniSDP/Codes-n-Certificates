openssl genpkey -algorithm Ed25519 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365 -subj '/CN=192.168.1.4' -addext "subjectAltName = IP:192.168.1.4"
echo "01" > file.srl
openssl x509 -req -in client.csr -CA server.crt -CAkey server.key -CAserial file.srl -out client.crt
