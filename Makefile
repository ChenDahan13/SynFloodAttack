all: attacker

attacker: attacker.c
	gcc attacker.c -o attacker

clean:
	rm attacker