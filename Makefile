NAME := zscaler-mitm
DIST := dist
STAGE := $(DIST)/$(NAME)
ZIP := $(DIST)/$(NAME).zip

.PHONY: package test clean icons

# Regenerate green/blue toolbar tints from icons/source-spy.png
icons:
	for color in green:'#1b5e20' blue:'#1565c0'; do \
	  name=$${color%%:*}; fill=$${color#*:}; \
	  for size in 16 32 48 128; do \
	    convert icons/source-spy.png -resize $${size}x$${size} \
	      -alpha extract -background "$$fill" -alpha shape \
	      icons/$${name}-$${size}.png; \
	  done; \
	done

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
