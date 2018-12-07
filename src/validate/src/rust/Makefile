all:
	cargo build
	cargo build --release
	[ -f query-rust ] || ln -s target/release/query-rust

clean:
	rm -rf target/debug target/release
