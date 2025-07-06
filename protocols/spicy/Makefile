GRAMMARS := $(wildcard parsers/*.spicy)

GEN_CC := $(notdir $(GRAMMARS:.spicy=.cc))
LINKER_CC := $(notdir $(patsubst parsers/%.spicy,spicy_linker_%.cc,$(GRAMMARS)))
HEADERS := $(patsubst parsers/%.spicy,parsers/%.h,$(GRAMMARS))

SPICY_FLAGS := -g
CXX ?= clang++
CXXFLAGS += -I/opt/spicy/include -std=c++17 -fPIC -O3 -DNDEBUG -fvisibility=hidden -I$(CURDIR)/parsers

.SECONDARY: $(GEN_CC) $(LINKER_CC) $(HEADERS)

%.cc: parsers/%.spicy
	@echo "spicyc -c $< -> $@"
	spicyc -c $(SPICY_FLAGS) $< -o $@

parsers/%.h: parsers/%.spicy
	@echo "spicyc -P parsers/$* -o $@ $<"
	spicyc -P parsers/$* -o $@ $<

spicy_linker_%.cc: parsers/%.spicy %.cc
	@echo "spicyc -l $< -> $@"
	spicyc -l $(SPICY_FLAGS) $< -o $@

.PHONY: all
all: $(GEN_CC) $(LINKER_CC) $(HEADERS)

.PHONY: clean
clean:
	rm -f $(GEN_CC) $(LINKER_CC) $(HEADERS)