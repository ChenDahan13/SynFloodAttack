all: attacker monitor 

attacker: attacker.c pbPlots.c supportLib.c
	gcc attacker.c pbPlots.c supportLib.c -lm -o attacker

monitor: monitor.c pbPlots.c supportLib.c
	gcc monitor.c pbPlots.c supportLib.c -lm -o monitor

clean:
	rm attacker monitor pbPlot supportLib