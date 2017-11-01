.PHONY: es

es:
	-cd elasticsearch && cmake -H. -Bbuild && cd ..