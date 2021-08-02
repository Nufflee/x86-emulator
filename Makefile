run: hello_world.bin
	cargo run

test:
	cargo test

hello_world.bin: hello_world.asm
	nasm -fbin $< -o $@

clean:
	rm -rf hello_world.bin