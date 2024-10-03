
.PHONY: build

# Define the default target
.DEFAULT_GOAL := help

# Help message
help:
	@echo "Usage: make <command> TARGET=<target>"
	@echo "Commands:"
	@echo "  build    Build the target"
	@echo "  generate Generate files"
	@echo "  clean-all Clean all the generated files and binary in all subdirectories"
	@echo "  run Run the target"
	@echo ""

generate: 
	@cd $(TARGET) && go generate .

build: generate
	@cd $(TARGET) && go build -a -o bin/ .

run: build 
	@cd $(TARGET) && sudo ./bin/$(notdir $(TARGET))
	
clean-all:
	@echo "Cleaning all files in subdirectories..."
	@find  -type f -name "bpf_bpf*" -delete
	@find ./*/bin/ -type f -executable -delete