# Vérifie que MODULE est défini, sinon affiche un message d'erreur
ifeq ($(MODULE),)
	$(error "Usage: make MODULE=<nom_du_fichier_sans_extension>")
endif

# Définition de obj-m avec le module spécifié
obj-m := $(MODULE).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean