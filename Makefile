all: attacker monitor 

attacker: attacker.c 
	gcc attacker.c -o attacker

monitor: monitor.c 
	gcc monitor.c -o monitor

clean:
	rm attacker monitor 