
.PHONY: build

# Define the default target
.DEFAULT_GOAL := help

TARGET ?= .
ARGS ?=
PROJECT_DIRS := tc-experiments tc xdp tracepoint


# Help message
help:
	@echo "Usage: make <command> TARGET=<target>"
	@echo "Commands:"
	@echo "  build    Build the target"
	@echo "  generate Generate files"
	@echo "  generate-all Generate files in the following folders and subfolders (tc, tc-experiments, tracepoint, xdp)"
	@echo "  clean-generate-all Delete generated files in the following folders and subfolders (tc, tc-experiments, tracepoint, xdp)"
	@echo "  clean-all Clean all the generated files and binary in all subdirectories"
	@echo "  run Run the target"
	@echo ""

generate: 
	@cd $(TARGET) && go generate .

# Run 'go generate' in directories with both go.mod and .c files
# Recursively check subdirectories (and sub-subdirectories, etc.) for these files
# For example, it will check directories like: tc-experiments/clsact_prio/clsact
generate-all:
	@for dir in $(PROJECT_DIRS); do \
		$(MAKE) -s generate-subdir dir=$$dir; \
	done

# Check if the subdirectory contains both go.mod and .c files, and run go generate
generate-subdir:
	@for subdir in $(dir)/*; do \
		if [ -d $$subdir ] && [ "$$(basename $$subdir)" != "bin" ]; then \
			if [ -f $$subdir/go.mod ] && [ -f $$subdir/*.c ]; then \
				echo "Running go generate in $$subdir"; \
				(cd $$subdir && go generate .); \
			else \
				echo "Skipping $$subdir, missing go.mod or .c file"; \
				$(MAKE) -s generate-subdir dir=$$subdir; \
			fi \
		fi \
	done

# Clean all generated files (e.g., bpf_*.go and *.o)
clean-generate-all:
	@for dir in $(PROJECT_DIRS); do \
		$(MAKE) -s clean-generated dir=$$dir; \
	done

# Clean generated files in subdirectories (e.g., bpf_*.go and *.o)
clean-generated:
	@for subdir in $(dir)/*; do \
		if [ -d $$subdir ] && [ "$$(basename $$subdir)" != "bin" ]; then \
			if [ -f $$subdir/go.mod ] && [ -f $$subdir/*.c ]; then \
				echo "Cleaning generated files in $$subdir"; \
				(cd $$subdir && rm -f bpf_*.go *.o); \
			else \
				echo "Skipping $$subdir, missing go.mod or .c file"; \
				$(MAKE) -s clean-generated dir=$$subdir; \
			fi \
		fi \
	done
	

build: generate
	@cd $(TARGET) && go build -a -o bin/ .

run: build
	@cd $(TARGET); \
	if [ -z "$(ARGS)" ]; then \
		sudo ./bin/$(notdir $(TARGET)); \
	else \
		sudo ./bin/$(notdir $(TARGET)) $(ARGS); \
	fi
	
clean-all:
	@echo "Cleaning all files in subdirectories..."
	@find  -type f -name "bpf_bpf*" -delete
	@find ./*/bin/ -type f -executable -delete

