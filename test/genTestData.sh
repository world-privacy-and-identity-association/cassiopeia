#!/bin/sh

fake_sigalg (){
    cat $1 | sed "s/IhvcNAQE/IhvcAAQE/" > $2
}

fake_sig (){
    cat $1 | sed "s/[^a]...=\$/caaa=/" | sed "s/a...=/baaa=/" |sed "s/caaa=/aaaa=/" > $2
}

mkdir -p testdata
openssl req -new -newkey rsa:2048 -nodes -keyout testdata/tmppriv.key -out testdata/test.csr -subj "/CN=bla" 2>/dev/null
openssl spkac -challenge a -key testdata/tmppriv.key -out testdata/test.spkac

for alg in csr spkac; do
    fake_sigalg testdata/test.$alg testdata/test_invalid_sig.$alg
    fake_sig testdata/test.$alg testdata/test_false_sig.$alg
done

openssl req -new -newkey rsa:2048 -nodes -subj "/CN=cn" -keyout testdata/server.key -out testdata/server.csr 2> /dev/null
openssl x509 -in testdata/server.csr -signkey testdata/server.key -req -out testdata/server.crt 2> /dev/null
