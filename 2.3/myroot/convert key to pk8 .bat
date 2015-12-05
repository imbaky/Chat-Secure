openssl pkcs8 -topk8 -in alice.key -out alice.pk8
REM pwd alice
openssl pkcs8 -topk8 -in bob.key -out bob.pk8
REM pwd bobkey
openssl pkcs8 -topk8 -in server.key -out server.pk8
REM pwd server