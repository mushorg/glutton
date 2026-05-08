GRAMMARS := $(wildcard parsers/*.spicy)

.DEFAULT_GOAL := all

GEN_CC := $(notdir $(GRAMMARS:.spicy=.cc))
LINKER_CC := spicy_linker.cc
HEADERS := $(patsubst parsers/%.spicy,parsers/%.h,$(GRAMMARS))

SPICY_FLAGS := -g
CXX ?= clang++
CXXFLAGS += -I/opt/spicy/include -std=c++20 -fPIC -O3 -DNDEBUG -fvisibility=hidden -I$(CURDIR)/parsers

.SECONDARY: $(GEN_CC) $(LINKER_CC) $(HEADERS)

%.cc: parsers/%.spicy
	@echo "spicyc -c $< -> $@"
	spicyc -c $(SPICY_FLAGS) $< -o $@

parsers/%.h: parsers/%.spicy
	@echo "spicyc -P parsers/$* -o $@ $<"
	spicyc -P parsers/$* -o $@ $<

$(LINKER_CC): $(GRAMMARS) $(GEN_CC)
	@echo "spicyc -l $(GRAMMARS) -> $@"
	spicyc -l $(SPICY_FLAGS) $(GRAMMARS) -o $@

.PHONY: all
all: $(GEN_CC) $(LINKER_CC) $(HEADERS)

.PHONY: clean
clean:
	rm -f $(GEN_CC) $(LINKER_CC) $(HEADERS)