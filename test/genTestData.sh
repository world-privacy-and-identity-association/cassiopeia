#!/bin/sh

fake_sigalg (){
    cat $1 | sed "s/IhvcNAQE/IhvcAAQE/" > $2
}

fake_sig (){
    cat $1 | sed "s/[^a]=\$/c=/" | sed "s/a=/b=/" |sed "s/c=/a=/" > $2
}

mkdir -p testdata
openssl req -new -newkey rsa:2048 -nodes -keyout testdata/tmppriv.key -out testdata/test.csr -subj "/CN=bla" 2>/dev/null
openssl spkac -challenge a -key testdata/tmppriv.key -out testdata/test.spkac

for alg in csr spkac; do
    fake_sigalg testdata/test.$alg testdata/test_invalid_sig.$alg
    fake_sig testdata/test.$alg testdata/test_false_sig.$alg
done
