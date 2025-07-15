# trabSo
antes de rodar crie o syscall_names.h

instale auditd

sudo apt install auditd

e depois utilize o comando para criar a syscall_names.h especifica do teu sistema

ausyscall --dump | awk 'NR > 1 {print "\"" $2 "\","}' > syscall_names.h



