NAME := zscaler-mitm
DIST := dist
STAGE := $(DIST)/$(NAME)
ZIP := $(DIST)/$(NAME).zip

.PHONY: package test clean

package: $(ZIP)

$(ZIP): manifest.json background.js cert.js popup.html popup.js $(wildcard icons/*.png)
	rm -rf $(STAGE) $(ZIP)
	mkdir -p $(STAGE)
	cp manifest.json background.js cert.js popup.html popup.js $(STAGE)/
	cp -r icons $(STAGE)/icons
	cd $(DIST) && zip -r $(NAME).zip $(NAME)
	@echo Wrote $(ZIP)

test:
	npm test

clean:
	rm -rf $(DIST)
