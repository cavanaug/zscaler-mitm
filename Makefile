NAME := zscaler-mitm
DIST := dist
STAGE := $(DIST)/$(NAME)
ZIP := $(DIST)/$(NAME).zip

.PHONY: package test clean icons

# Tint from default-128 so every color uses the same toolbar glyph
# (source-spy.png is padded; resizing it shrinks the spy vs yellow/red).
icons:
	for color in green:'#43a047' blue:'#1565c0'; do \
	  name=$${color%%:*}; fill=$${color#*:}; \
	  for size in 16 32 48 128; do \
	    convert icons/default-128.png -resize $${size}x$${size} \
	      -alpha extract -background "$$fill" -alpha shape \
	      icons/$${name}-$${size}.png; \
	  done; \
	done

package: $(ZIP)

$(ZIP): manifest.json background.js cert.js tab-match.js debug.js overlay-store.js popup.html popup.js options.html options.js public-cas.json $(wildcard icons/*.png)
	rm -rf $(STAGE) $(ZIP)
	mkdir -p $(STAGE)
	cp manifest.json background.js cert.js tab-match.js debug.js overlay-store.js popup.html popup.js options.html options.js public-cas.json $(STAGE)/
	cp -r icons $(STAGE)/icons
	cd $(DIST) && zip -r $(NAME).zip $(NAME)
	@echo Wrote $(ZIP)

test:
	npm test

clean:
	rm -rf $(DIST)
