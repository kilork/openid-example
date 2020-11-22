if [ -e .env.microsoft ]; then
    source .env.microsoft
fi

cargo run --features microsoft --example microsoft